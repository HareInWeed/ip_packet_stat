use anyhow::Result;

use chrono::prelude::*;

use nwd::NwgUi;
use nwg::{
    NativeUi, 
    stretch::{
        geometry::{Size, Rect}, 
        style::{Dimension as D, FlexDirection, AlignItems}
    }
};

use packet::{Packet, ip::{v4, Protocol}, udp, tcp};
use byteorder::{self, NetworkEndian, WriteBytesExt};

use crate::{socket::Capturer, utils::AppProtocol};

use crate::record::Record;

use crate::filter::{FilterError, create_filter};

use crate::utils::attach_console;

use ipconfig::{Adapter, OperStatus};

use std::{cell::RefCell, net::SocketAddr, time::Duration};

// The numbers here are the index of each tab,  
// and they purposely match the UI declared below.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Record = 0,
    Plot = 1,
    Stat = 2,
    About = 3,
}

impl Default for Mode {
    fn default() -> Self {
        Self::About
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
    filter: Option<Box<dyn Fn(&Record) -> bool>>
}

const PT_0: D = D::Points(0.0);
const PT_10: D = D::Points(10.0);
const MARGIN_TRL: Rect<D> = Rect {
    start: PT_10,
    end: PT_10,
    top: PT_10,
    bottom: PT_0
};

#[derive(Default, NwgUi)]
pub struct App {
    state: RefCell<State>,
    capturer: RefCell<Capturer>,

    #[nwg_control(title: "IP流量分析器", size: (900, 580), 
        icon: nwg::EmbedResource::load(None).unwrap().icon_str("LOGO", None).as_ref()
    )]
    #[nwg_events( OnWindowClose: [Self::window_close], OnInit: [Self::init] )]
    window: nwg::Window,

    #[nwg_control(parent: window, interval: Duration::from_millis(10))]
    #[nwg_events( OnTimerTick: [Self::tick] )]
    polling_timer: nwg::AnimationTimer,

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
        min_size: Size { width: D::Undefined, height: D::Points(30.0) },
        margin: MARGIN_TRL,
    )]
    interface_row_frame: nwg::Frame,

    #[nwg_control(parent: interface_row_frame)]
    #[nwg_layout(parent: interface_row_frame,
        align_items: AlignItems::Stretch,
        flex_direction: FlexDirection::Row, padding: Default::default()
    )]
    interface_row: nwg::FlexboxLayout,

    #[nwg_control(parent: interface_row_frame)]
    #[nwg_layout_item(layout: interface_row, flex_grow: 1.0,
        margin: Rect { end: D::Points(10.0), ..Default::default() }
    )]
    #[nwg_events(OnComboxBoxSelection: [Self::connect_interface])]
    interfaces: nwg::ComboBox<String>,

    #[nwg_control(parent: interface_row_frame, text: "开始捕获")]
    #[nwg_layout_item(layout: interface_row,
        size: Size { width: D::Points(100.0), height: D::Auto },
    )]
    #[nwg_events(MousePressLeftUp: [Self::toggle_capture])]
    capture: nwg::Button,

    // ----- capturing setting row -----
    #[nwg_control(parent: window, flags: "VISIBLE")]
    #[nwg_layout_item(layout: main_column,
        min_size: Size { width: D::Undefined, height: D::Points(30.0) },
        margin: MARGIN_TRL,
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
        flex_grow: 1.0,
        min_size: Size { width: D::Undefined, height: D::Points(30.0) },
        margin: Rect { end: D::Points(10.0), ..Default::default() }
    )]
    #[nwg_events(OnTextInput: [Self::create_filter])]
    filter: nwg::TextInput,

    #[nwg_control(parent: capturing_setting_row_frame, placeholder_text: Some("请输入捕获时间（毫秒）"))]
    #[nwg_layout_item(layout: capturing_setting_row,
        min_size: Size { width: D::Points(180.0), height: D::Points(30.0) },
    )]
    #[nwg_events(OnTextInput: [Self::set_timeout])]
    timeout: nwg::TextInput,

    // ----- tab container -----
    #[nwg_control(parent: window, flags: "VISIBLE")]
    #[nwg_layout_item(layout: main_column,
        flex_grow: 1.0,
        min_size: Size { width: D::Undefined, height: D::Points(30.0) },
        margin: MARGIN_TRL,
    )]
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
        flex_direction: FlexDirection::Column, 
    )]
    plot_tab_layout: nwg::FlexboxLayout,

    #[nwg_control(parent: plot_tab, text: "Plot", h_align: nwg::HTextAlign::Center)]
    #[nwg_layout_item(layout: plot_tab_layout)]
    plot_placeholder: nwg::Label,

    // ----- stat tab -----
    #[nwg_control(parent: tabs_container, text: "统计结果")]
    stat_tab: nwg::Tab,

    #[nwg_control(parent: stat_tab)]
    #[nwg_layout(parent: stat_tab,
        flex_direction: FlexDirection::Column, 
    )]
    stat_tab_layout: nwg::FlexboxLayout,

    #[nwg_control(parent: stat_tab, text: "Stat", h_align: nwg::HTextAlign::Center)]
    #[nwg_layout_item(layout: stat_tab_layout)]
    stat_placeholder: nwg::Label,

    // ----- about tab -----
    #[nwg_control(parent: tabs_container, text: "关于")]
    about_tab: nwg::Tab,

    #[nwg_control(parent: about_tab)]
    #[nwg_layout(parent: about_tab,
        flex_direction: FlexDirection::Row, 
    )]
    about_tab_layout: nwg::FlexboxLayout,

    // #[nwg_control(parent: about_tab, text: "About", h_align: nwg::HTextAlign::Center)]
    // #[nwg_layout_item(layout: about_tab_layout)]
    // about_placeholder: nwg::Label,

    #[nwg_control(parent: about_tab, size: (128, 128),
        background_color: Some([0xff, 0xff, 0xff]),
        icon: nwg::EmbedResource::load(None).unwrap().icon_str("LOGO", None).as_ref()
    )]
    #[nwg_layout_item(layout: about_tab_layout,
        size: Size { width: D::Points(64.0), height: D::Points(64.0) },
    )]
    logo: nwg::ImageFrame,

    // ----- status bar -----
    #[nwg_control(parent: window, text: "准备就绪")]
    #[nwg_layout_item(layout: main_column, 
        margin: Rect { top: D::Points(10.0), ..Default::default() },
        min_size: Size { width: D::Undefined, height: D::Points(30.0) },
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
        {
            let mut state = self.state.borrow_mut();
            state.capturing = true;
            state.records.clear();
            state.start_time = Some(Local::now());
        }
        self.capture.set_text("停止捕获");
        self.record_table.clear();
        self.reset_status_bar();
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
        }
    }

    fn create_filter(&self) {
        let filter_str = self.filter.text();
        if filter_str.is_empty() { 
            self.state.borrow_mut().filter = None;
            self.rebuild_record_list();
        } else {
            match create_filter(filter_str.as_str()) {
                Ok(filter) => {
                    self.state.borrow_mut().filter = Some(Box::new(filter));
                    self.rebuild_record_list();
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

    fn rebuild_record_list(&self) {
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

    fn update_record(&self, record: Record) {
        let mut state = self.state.borrow_mut();
        if let Some(f) = state.filter.as_ref() {
            if f(&record) {
                self.record_table.insert_items_row(None, &record.to_string_array());
            }
        } else {
            self.record_table.insert_items_row(None, &record.to_string_array());
        }
        state.records.push(record);
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
