use anyhow::Result;

use nwd::NwgUi;
use nwg::NativeUi;

use crate::socket::{self, ipv4_sniffer};
use socket2::Socket;
use std::{cell::RefCell, time::Duration};

#[derive(Default)]
pub struct State {
    socket: Option<Socket>,
    buffer: Vec<u8>,
    capturing: bool,
}

#[derive(NwgUi)]
pub struct App {
    state: RefCell<State>,

    #[nwg_control(size: (300, 115), position: (300, 300), title: "Basic example", flags: "WINDOW|VISIBLE")]
    #[nwg_events( OnWindowClose: [Self::window_close] )]
    window: nwg::Window,

    #[nwg_control(parent: window, interval: Duration::from_millis(1000/60))]
    #[nwg_events( OnTimerTick: [Self::tick] )]
    timer: nwg::AnimationTimer,
}

impl App {
    fn new() -> Self {
        let mut state = State::default();
        state.capturing = false;
        Self {
            state: RefCell::new(state),
            window: Default::default(),
            timer: Default::default(),
        }
    }

    fn tick(&self) {
        todo!()
    }

    fn window_close(&self) {
        nwg::stop_thread_dispatch();
    }
}

pub fn main() -> Result<()> {
    nwg::init()?;
    nwg::Font::set_global_family("Segoe UI")?;
    let _app = App::build_ui(App::new())?;
    nwg::dispatch_thread_events();
    Ok(())
}
