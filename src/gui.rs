use anyhow::Result;

use chrono::prelude::*;

use nwd::NwgUi;
use nwg::{
    NativeUi, 
    stretch::{
        self, geometry::Rect, 
        style::{Dimension, FlexDirection, AlignItems, JustifyContent}
    }
};

use plotters::prelude::*;

use packet::{Packet, ip::{v4, Protocol}, udp, tcp};
use byteorder::{self, NetworkEndian, WriteBytesExt};

use crate::{
    filter::{FilterError, create_filter},
    meta,
    record::{Record, StatRecord},
    rect, size,
    socket::Capturer,
    utils::{AppProtocol, attach_console}
};

use ipconfig::{Adapter, OperStatus};

use std::{cell::RefCell, iter, net::SocketAddr, time::Duration};

// The numbers here are the index of each tab,  
// and they purposely match the UI declared below.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Record = 0,
    Plot = 1,
    Stat = 2,
    About = 3,
}

impl Default for Mode {
    fn default() -> Self {
        Self::Record
    }
}

impl From<usize> for Mode {
    fn from(idx: usize) -> Self {
        match idx {
            0 => Self::Record,
            1 => Self::Plot,
            2 => Self::Stat,
            3 => Self::About,
            _ => unreachable!(),
        }
    }
}

#[derive(Default)]
pub struct State {
    interfaces: Vec<Adapter>,
    capturing: bool,

    records: Vec<Record>,
    start_time: Option<DateTime<Local>>,
    end_time: Option<DateTime<Local>>,
    
    mode: Mode,
    filter: Option<Box<dyn Fn(&Record) -> bool>>,
}

const MARGIN_TSE: Rect<Dimension> = rect!{10.0, 10.0, 0.0};

#[derive(Default, NwgUi)]
pub struct App {
    state: RefCell<State>,
    capturer: RefCell<Capturer>,
    stat_records: RefCell<StatRecord>,

    #[nwg_resource(module: None)]
    embed_resource: nwg::EmbedResource,

    #[nwg_resource(
        source_embed: Some(&data.embed_resource),
        source_embed_str: Some("LOGO"),
        size: Some((32, 32))
    )]
    window_icon: nwg::Icon,

    #[nwg_control(title: "IP流量分析器", size: (900, 580),
        icon: Some(&data.window_icon)
    )]
    #[nwg_events(
        OnInit: [Self::init],
        // Enable this makes plot update whenever window is resized.
        // But without throttling this won't be much responsive.
        // TODO: add throttling for replotting
        // OnResize: [Self::window_resize],
        OnWindowClose: [Self::window_close],
    )]
    window: nwg::Window,

    #[nwg_control(parent: window, interval: Duration::from_millis(10))]
    #[nwg_events( OnTimerTick: [Self::tick] )]
    polling_timer: nwg::AnimationTimer,

    #[nwg_control(parent: window, interval: Duration::from_millis(1000))]
    #[nwg_events( OnTimerTick: [Self::rebuild_plot_graph] )]
    plotting_timer: nwg::AnimationTimer,

    #[nwg_control(parent: window, interval: Duration::from_millis(1))]
    #[nwg_events( OnTimerStop: [Self::stop_capture] )]
    capturing_timer: nwg::AnimationTimer,

    // ----- main column -----
    #[nwg_control()]
    #[nwg_layout(parent: window, flex_direction: FlexDirection::Column)]
    main_column: nwg::FlexboxLayout,

    // ----- interface row -----
    #[nwg_control(parent: window, flags: "VISIBLE")]
    #[nwg_layout_item(layout: main_column,
        min_size: size!{height: 30.0},
        margin: MARGIN_TSE,
    )]
    interface_row_frame: nwg::Frame,

    #[nwg_control(parent: interface_row_frame)]
    #[nwg_layout(parent: interface_row_frame,
        align_items: AlignItems::Stretch,
        flex_direction: FlexDirection::Row, padding: Default::default()
    )]
    interface_row: nwg::FlexboxLayout,

    #[nwg_control(parent: interface_row_frame)]
    #[nwg_layout_item(layout: interface_row, flex_grow: 1.0, margin: rect!{end: 10.0})]
    #[nwg_events(OnComboxBoxSelection: [Self::connect_interface])]
    interfaces: nwg::ComboBox<String>,

    #[nwg_control(parent: interface_row_frame, text: "开始捕获")]
    #[nwg_layout_item(layout: interface_row, size: size!{100.0, auto})]
    #[nwg_events(MousePressLeftUp: [Self::toggle_capture])]
    capture: nwg::Button,

    // ----- capturing setting row -----
    #[nwg_control(parent: window, flags: "VISIBLE")]
    #[nwg_layout_item(layout: main_column,
        min_size: size!{height: 30.0}, margin: MARGIN_TSE,
    )]
    capturing_setting_row_frame: nwg::Frame,

    #[nwg_control(parent: capturing_setting_row_frame)]
    #[nwg_layout(parent: capturing_setting_row_frame,
        align_items: AlignItems::Stretch,
        flex_direction: FlexDirection::Row, padding: Default::default()
    )]
    capturing_setting_row: nwg::FlexboxLayout,

    #[nwg_control(parent: capturing_setting_row_frame, placeholder_text: Some("请输入筛选器"))]
    #[nwg_layout_item(layout: capturing_setting_row,
        flex_grow: 1.0, min_size: size!{height: 30.0}, margin: rect!{end: 10.0}
    )]
    #[nwg_events(OnTextInput: [Self::create_filter])]
    filter: nwg::TextInput,

    #[nwg_control(parent: capturing_setting_row_frame, placeholder_text: Some("请输入捕获时间（毫秒）"))]
    #[nwg_layout_item(layout: capturing_setting_row, min_size: size!{180.0, 30.0})]
    #[nwg_events(OnTextInput: [Self::set_timeout])]
    timeout: nwg::TextInput,

    // ----- tab container -----
    #[nwg_control(parent: window, flags: "VISIBLE")]
    #[nwg_layout_item(layout: main_column,
        flex_grow: 1.0,
        min_size: size!{height: 30.0},
        margin: MARGIN_TSE,
    )]
    #[nwg_events(TabsContainerChanged: [Self::tab_changed])]
    tabs_container: nwg::TabsContainer,

    // ----- record tab -----
    #[nwg_control(parent: tabs_container, text: "捕获记录")]
    record_tab: nwg::Tab,

    #[nwg_control(parent: record_tab)]
    #[nwg_layout(parent: record_tab,
        flex_direction: FlexDirection::Column, 
    )]
    record_tab_layout: nwg::FlexboxLayout,

    #[nwg_control(parent: record_tab, list_style: nwg::ListViewStyle::Detailed, focus: true,
        ex_flags: nwg::ListViewExFlags::GRID | nwg::ListViewExFlags::FULL_ROW_SELECT, 
    )]
    #[nwg_layout_item(layout: record_tab_layout)]
    record_table: nwg::ListView,

    // ----- plot tab -----
    #[nwg_control(parent: tabs_container, text: "流量图表")]
    plot_tab: nwg::Tab,

    #[nwg_control(parent: plot_tab)]
    #[nwg_layout(parent: plot_tab,
        flex_direction: FlexDirection::Row, 
    )]
    plot_tab_layout: nwg::FlexboxLayout,

    #[nwg_control(parent: plot_tab)]
    #[nwg_layout_item(layout: plot_tab_layout, flex_grow: 1.0)]
    plot_graph: nwg::Plotters,

    // ----- stat tab -----
    #[nwg_control(parent: tabs_container, text: "统计结果")]
    stat_tab: nwg::Tab,

    #[nwg_control(parent: stat_tab)]
    #[nwg_layout(parent: stat_tab,
        flex_direction: FlexDirection::Column, 
    )]
    stat_tab_layout: nwg::FlexboxLayout,

    #[nwg_control(parent: stat_tab, text: "统计结果", background_color: Some([0xff, 0xff, 0xff]))]
    #[nwg_layout_item(layout: stat_tab_layout,
        min_size: size!{height: 30.0},
    )]
    stat_net_info: nwg::Label,

    #[nwg_control(parent: stat_tab, text: "传输层统计结果", background_color: Some([0xff, 0xff, 0xff]))]
    #[nwg_layout_item(layout: stat_tab_layout,
        min_size: size!{height: 30.0},
    )]
    stat_trans_label: nwg::Label,

    #[nwg_control(parent: stat_tab, list_style: nwg::ListViewStyle::Detailed, focus: true,
        ex_flags: nwg::ListViewExFlags::GRID | nwg::ListViewExFlags::FULL_ROW_SELECT, 
    )]
    #[nwg_layout_item(layout: stat_tab_layout, flex_grow: 1.0)]
    stat_trans_table: nwg::ListView,

    #[nwg_control(parent: stat_tab, text: "应用层统计结果", background_color: Some([0xff, 0xff, 0xff]))]
    #[nwg_layout_item(layout: stat_tab_layout,
        min_size: size!{height: 30.0},
    )]
    stat_app_label: nwg::Label,

    #[nwg_control(parent: stat_tab, list_style: nwg::ListViewStyle::Detailed, focus: true,
        ex_flags: nwg::ListViewExFlags::GRID | nwg::ListViewExFlags::FULL_ROW_SELECT, 
    )]
    #[nwg_layout_item(layout: stat_tab_layout, flex_grow: 1.0)]
    stat_app_table: nwg::ListView,

    // ----- about tab -----
    #[nwg_control(parent: tabs_container, text: "关于")]
    about_tab: nwg::Tab,

    #[nwg_resource(family: "Segoe UI", size: 30)]
    about_font: nwg::Font,

    #[nwg_control(parent: about_tab)]
    #[nwg_layout(parent: about_tab,
        align_items: AlignItems::Center,
        justify_content: JustifyContent::Center,
        flex_direction: FlexDirection::Row, 
    )]
    about_tab_layout: nwg::FlexboxLayout,

    #[nwg_resource(
        source_embed: Some(&data.embed_resource),
        source_embed_str: Some("LOGO"),
        size: Some((128, 128))
    )]
    app_logo: nwg::Icon,

    #[nwg_control(parent: about_tab, size: (128, 128),
        background_color: Some([0xff, 0xff, 0xff]),
        icon: Some(&data.app_logo),
    )]
    #[nwg_layout_item(layout: about_tab_layout, size: size!{128.0, 128.0})]
    about_logo: nwg::ImageFrame,

    #[nwg_control(parent: about_tab,
        background_color: Some([0xff, 0xff, 0xff]),
        text: format!(
r"{} {}
by {}

",
        meta::NAME, meta::VERSION, meta::AUTHORS).as_str(),
    )]
    #[nwg_layout_item(layout: about_tab_layout, size: size!{200.0, 180.0})]
    about_info: nwg::Label,

    // ----- status bar -----
    #[nwg_control(parent: window, text: "准备就绪")]
    #[nwg_layout_item(layout: main_column, 
        margin: rect!{top: 10.0},
        min_size: size!{height: 30.0}
    )]
    status_bar: nwg::StatusBar,
}

impl App {
    fn new() -> Result<Self> {
        let mut state = State::default();
        state.capturing = false;
        state.interfaces = {
            let mut interfaces = ipconfig::get_adapters()?
                .into_iter()
                .filter(|adapter| {
                    adapter.oper_status() == OperStatus::IfOperStatusUp
                        && adapter.ip_addresses().iter().any(|addr| addr.is_ipv4())
                })
                .collect::<Vec<_>>();
            interfaces.sort_by(|a1, a2| a1.description().cmp(a2.description()));
            interfaces
        };

        Ok(Self {
            state: RefCell::new(state),
            ..Default::default()
        })
    }

    fn reset_status_bar(&self) {
        let capturing = self.state.borrow().capturing;
        if capturing {
            self.status_bar.set_text(0, "正在捕获...");
        } else {
            self.status_bar.set_text(0, "准备就绪");
        }
    }

    fn init(&self) {
        let state = self.state.borrow();
        for (i, adapter) in state.interfaces.iter().enumerate() {
            self.interfaces.insert(i, adapter.description().to_string());
        }

        self.tabs_container.set_selected_tab(state.mode as usize);

        // ----- record tab -----
        self.record_table.insert_column("时间");
        self.record_table.set_column_width(0, 220);
        self.record_table.insert_column("源IP");
        self.record_table.set_column_width(1, 135);
        self.record_table.insert_column("源端口");
        self.record_table.set_column_width(2, 60);
        self.record_table.insert_column("目的IP");
        self.record_table.set_column_width(3, 135);
        self.record_table.insert_column("目的端口");
        self.record_table.set_column_width(4, 80);
        self.record_table.insert_column("IP分组长度");
        self.record_table.insert_column("IP数据长度");
        self.record_table.insert_column("传输层协议");
        self.record_table.insert_column("报文段数据长度");
        self.record_table.set_column_width(8, 120);
        self.record_table.insert_column("应用层协议");
        self.record_table.set_headers_enabled(true);

        // ----- stat tab -----
        self.stat_trans_table.insert_column("协议");
        self.stat_trans_table.insert_column("分组数量");
        self.stat_trans_table.insert_column("字节数");
        self.stat_trans_table.insert_column("网络层上传输的字节数");
        self.stat_trans_table.set_column_width(3, 180);
        self.stat_trans_table.set_headers_enabled(true);

        self.stat_app_table.insert_column("协议");
        self.stat_app_table.insert_column("分组数量");
        self.stat_app_table.insert_column("字节数");
        self.stat_app_table.insert_column("网络层上传输的字节数");
        self.stat_app_table.set_column_width(3, 180);
        self.stat_app_table.insert_column("传输层上传输的字节数");
        self.stat_app_table.set_column_width(4, 180);
        self.stat_app_table.set_headers_enabled(true);

        // ----- about tab -----
        self.about_info.set_font(Some(&self.about_font));
    }

    fn connect_interface(&self) {
        if let Some(idx) = self.interfaces.selection() {
            let addr = self.state.borrow()
                .interfaces[idx].ip_addresses().iter()
                .find(|&addr| addr.is_ipv4())
                .map(|addr| addr.clone());
            if let Some(interface_addr) = addr {
                let address = SocketAddr::from((interface_addr.clone(), 8000));
                let mut capturer = self.capturer.borrow_mut();
                if let Err(err) = capturer.capture(address, true) {
                    match err.raw_os_error() {
                        Some(10013) => self.status_bar.set_text(0, "没有管理员权限，请以管理员权限重新运行程序"),
                        _ => self.status_bar.set_text(0, format!("未知错误：{}", err).as_str())
                    }
                } else {
                    self.reset_status_bar();
                }
            } else {
                self.status_bar.set_text(0, "没有可用 ipv4 地址，请选择其他网卡");
            }
        }
    }

    fn tab_changed(&self) {
        let mode: Mode = self.tabs_container.selected_tab().into();
        if mode != Mode::Plot {
            self.plotting_timer.stop();
        }
        match mode {
            Mode::Record => self.rebuild_record_table(),
            Mode::Plot => self.plotting_timer.start(),
            Mode::Stat => self.display_stat_table(),
            Mode::About => {},
        };
        self.state.borrow_mut().mode = mode;
    }

    fn set_timeout(&self) {
        let text = self.timeout.text();
        let text = text.trim();
        if text.is_empty() {
            self.capturing_timer.set_lifetime(None);
        } else {
            if let Ok(timeout) = text.parse::<u64>() {
                self.capturing_timer.set_lifetime(Some(Duration::from_millis(timeout)));
            } else {
                self.capturing_timer.set_lifetime(None);
                self.status_bar.set_text(0, "捕获时间不正确");
                return;
            }
        }
        self.reset_status_bar();
    }

    fn start_capture(&self) {
        self.capture.set_text("停止捕获");
        self.reset_status_bar();
        self.record_table.clear();
        {
            let mut state = self.state.borrow_mut();
            state.capturing = true;
            state.records.clear();
            self.stat_records.borrow_mut().clear();
            state.end_time = None;
            state.start_time = Some(Local::now());
        }
        self.capturing_timer.start();
        self.polling_timer.start();
    }

    fn stop_capture(&self) {
        self.polling_timer.stop();
        self.capturing_timer.stop();
        {
            let mut state = self.state.borrow_mut();
            state.capturing = false;
            state.end_time = Some(Local::now());
        }
        self.capture.set_text("开始捕获");
        self.reset_status_bar();
    }

    fn toggle_capture(&self) {
        let capturing = self.state.borrow().capturing;
        let capturer = self.capturer.borrow();
        if capturer.connected() {
            if capturing {
                self.stop_capture();
            } else {
                self.start_capture();
            }
        } else {
            self.status_bar.set_text(0, "请首先选择网卡");
        }
    }

    fn create_filter(&self) {
        let filter_str = self.filter.text();
        if filter_str.is_empty() { 
            self.state.borrow_mut().filter = None;
            self.rebuild_record_table();
            self.sync_stat_data();
            self.display_stat_table();
        } else {
            match create_filter(filter_str.as_str()) {
                Ok(filter) => {
                    self.state.borrow_mut().filter = Some(Box::new(filter));
                    self.rebuild_record_table();
                    self.sync_stat_data();
                    self.display_stat_table();
                },
                Err(err) => {
                    match err {
                        FilterError::InvalidLiteral(literal) => {
                            self.status_bar.set_text(0, format!("这里不能用值 \"{}\" 来筛选", literal).as_str())
                        },
                        FilterError::InvalidField(field) => {
                            self.status_bar.set_text(0, format!("名为 \"{}\" 的项目不存在", field).as_str())
                        },
                        FilterError::InvalidOperator(op) => {
                            self.status_bar.set_text(0, format!("\"{}\" 不是一个合法的操作", op).as_str())
                        },
                        FilterError::UnsupportedOperator(field, op) => {
                            self.status_bar.set_text(0, format!("不能在 \"{}\" 项目上使用 \"{}\" 操作筛选", field, op).as_str())
                        },
                        FilterError::Failed | FilterError::Nom(_, _) => {
                            self.status_bar.set_text(0, "筛选器不合法")
                        }
                    }
                    return;
                },
            }
        }
        self.reset_status_bar();
    }

    fn sync_stat_data(&self) {
        let state = self.state.borrow();
        let mut state_records = self.stat_records.borrow_mut();
        state_records.clear();
        if let Some(f) = state.filter.as_ref() {
            state_records.update_multiple(state.records.iter().filter(|r| f(r)));
        } else {
            state_records.update_multiple(state.records.iter());
        };
    }

    fn rebuild_record_table(&self) {
        self.record_table.clear();
        let state = self.state.borrow();
        let mut records_iter = state.records.iter();
        let mut records_filter_iter;
        let iter: &mut dyn Iterator<Item = &Record> = if let Some(f) = state.filter.as_ref() {
            records_filter_iter = records_iter.filter(|&r| f(r));
            &mut records_filter_iter
        } else {
            &mut records_iter
        };
        for record in iter {
            self.record_table.insert_items_row(None, &record.to_string_array());
        }
    }

    fn rebuild_plot_graph(&self) {
        if let Err(_err) = self.rebuild_plot_graph_with_result() {
            // we can not print here if no console is available
            // eprintln!("{:?}", _err);
        }
    }

    fn rebuild_plot_graph_with_result(&self) -> Result<()> {
        let graph = self.plot_graph.draw()?;

        let mut plot = ChartBuilder::on(&graph)
            .caption("y=x^2", ("sans-serif", 50).into_font())
            .margin(-15)
            .x_label_area_size(30)
            .y_label_area_size(30)
            .build_cartesian_2d(-1f32..1f32, -0.1f32..1f32)?;

        plot.configure_mesh()
            .light_line_style(ShapeStyle { color: TRANSPARENT, filled: false, stroke_width: 0 })
            .draw()?;

        plot
            .draw_series(LineSeries::new(
                (-50..=50).map(|x| x as f32 / 50.0).map(|x| (x, x * x)),
                &RED,
            ))?
            .label("y = x^2")
            .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], &RED));

        plot
            .configure_series_labels()
            .background_style(&WHITE.mix(0.8))
            .border_style(&BLACK)
            .draw()?;
        Ok(())
    }

    fn display_stat_table(&self) {
        let stat_records = self.stat_records.borrow();
        self.stat_net_info.set_text(format!(
            "统计结果：{} 个 IPv4 分组，共 {} 字节", 
            stat_records.stat_net_table.packet_num, 
            stat_records.stat_net_table.byte_num
        ).as_str());

        self.stat_trans_table.clear();
        let mut trans_records = stat_records.stat_trans_table.iter().collect::<Vec<_>>();
        trans_records.sort_by(|a, b| a.0.cmp(b.0));
        for (idx, (proto, record)) in trans_records.into_iter().enumerate() {
            let row = iter::once(proto.clone()).chain(record.to_string_array().into_iter()).collect::<Vec<_>>();
            self.stat_trans_table.insert_items_row(Some(idx as i32), row.as_slice());
        }

        self.stat_app_table.clear();
        let mut app_records = stat_records.stat_app_table.iter().collect::<Vec<_>>();
        app_records.sort_by(|a, b| a.0.cmp(b.0));
        for (idx, (proto, record)) in app_records.into_iter().enumerate() {
            let row = iter::once(proto.clone()).chain(record.to_string_array().into_iter()).collect::<Vec<_>>();
            self.stat_app_table.insert_items_row(Some(idx as i32), row.as_slice());
        }
    }

    fn update_record(&self, record: Record) {
        self.state.borrow_mut().records.push(record.clone());

        if let Some(f) = self.state.borrow().filter.as_ref() {
            if !f(&record) {
                return;
            }
        }

        self.stat_records.borrow_mut().update(&record);

        let mode = self.state.borrow().mode;

        match mode {
            Mode::Record => self.update_record_table(&record),
            Mode::Plot => self.update_plot_graph(&record),
            Mode::Stat => self.display_stat_table(),
            Mode::About => {},
        }
    }

    fn update_record_table(&self, record: &Record) {
        self.record_table.insert_items_row(None, &record.to_string_array());
    }

    fn update_plot_graph(&self, _record: &Record) {
        self.rebuild_plot_graph();
    }

    fn tick(&self) {
        let time = Local::now();
        let mut capturer = self.capturer.borrow_mut();
        if let Ok(raw_packet) = capturer.read_mut() {
            let len = raw_packet.len();
            if len == 0 {
                return;
            }
            let mut record = Record {
                time,
                src_ip: None,
                src_port: None,
                dest_ip: None,
                dest_port: None,
                len: len as u16,
                ip_payload_len: None,
                trans_proto: Protocol::Unknown(0),
                trans_payload_len: None,
                app_proto: AppProtocol::Unknown,
            };
            if let Ok(mut ip_packet) = v4::Packet::new(&raw_packet[..]) {
                if ip_packet.length() < 20 {
                    // corrupted ipv4 packet, try to recover packet
                    if len > 4 {
                        // TODO: handle the error, although this is unlikely to happen
                        let _ = (&mut raw_packet[2..]).write_u16::<NetworkEndian>(len as u16);
                        ip_packet = v4::Packet::unchecked(raw_packet);
                    }
                }
                let ip_payload_len = ip_packet.payload().len();
                let have_payload = ip_payload_len != 0;

                record.ip_payload_len = Some(ip_payload_len as u16);
                record.src_ip = Some(ip_packet.source());
                record.dest_ip = Some(ip_packet.destination());
                record.trans_proto = ip_packet.protocol();
                match ip_packet.protocol() {
                    Protocol::Tcp if have_payload => {
                        if let Ok(tcp_packet) = tcp::Packet::new(ip_packet.payload()) {
                            let src_port = tcp_packet.source();
                            let dest_port = tcp_packet.destination();
                            record.trans_payload_len = Some(tcp_packet.payload().len() as u16);
                            record.src_port = Some(src_port);
                            record.dest_port = Some(dest_port);
                            record.app_proto = AppProtocol::from((src_port, dest_port));
                        }
                    }
                    Protocol::Udp if have_payload => {
                        if let Ok(udp_packet) = udp::Packet::new(ip_packet.payload()) {
                            let src_port = udp_packet.source();
                            let dest_port = udp_packet.destination();
                            record.trans_payload_len = Some(udp_packet.payload().len() as u16);
                            record.src_port = Some(src_port);
                            record.dest_port = Some(dest_port);
                            record.app_proto = AppProtocol::from((src_port, dest_port));
                        }
                    }
                    _ => {},
                };
            }
            self.update_record(record);
        }
    }

    fn window_resize(&self) {
        if { self.state.borrow().mode } == Mode::Plot {
            self.rebuild_plot_graph()
        }
    }

    fn window_close(&self) {
        nwg::stop_thread_dispatch();
    }
}

fn gui_main() -> Result<()> {
    let _ = attach_console();
    let font = {
        let mut font = nwg::Font::default();
        nwg::Font::builder()
            .family("Segoe UI")
            .size(22)
            .build(&mut font)?;
        font
    };
    nwg::Font::set_global_default(Some(font));
    let _app = App::build_ui(App::new()?)?;
    nwg::dispatch_thread_events();
    Ok(())
}

pub fn main() -> Result<()> {
    nwg::init()?;
    match gui_main() {
        Ok(_) => Ok(()),
        Err(err) => nwg::fatal_message("fatal error", err.to_string().as_str()),
    }
}
