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
    ticking: bool,
    counter: i32,
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

    #[nwg_layout(parent: window, spacing: 1)]
    grid: nwg::GridLayout,

    #[nwg_control(text: "Heisenberg", focus: true)]
    #[nwg_layout_item(layout: grid, row: 0, col: 0)]
    name_edit: nwg::TextInput,

    #[nwg_control(text: "Toggle Timer")]
    #[nwg_layout_item(layout: grid, col: 0, row: 1)]
    #[nwg_events( MousePressLeftUp: [Self::ticking_toggle] )]
    hello_button: nwg::Button,
}

impl App {
    fn new() -> Self {
        let mut state = State::default();
        state.ticking = false;
        Self {
            state: RefCell::new(state),
            window: Default::default(),
            timer: Default::default(),
            grid: Default::default(),
            name_edit: Default::default(),
            hello_button: Default::default(),
        }
    }

    fn tick(&self) {
        let mut state = self.state.borrow_mut();
        state.counter += 1;
        self.name_edit.set_text(state.counter.to_string().as_str());
    }

    fn ticking_toggle(&self) {
        let mut state = self.state.borrow_mut();
        state.ticking = !state.ticking;
        if state.ticking {
            state.counter = 0;
            self.timer.start();
        } else {
            self.timer.stop();
        }
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
