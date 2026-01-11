//! x86_64 I/O Compartment
//!
//! This module handles input/output devices:
//! - **Serial** - COM1 serial port for early debug output
//! - **VGA** - Text-mode VGA buffer for screen output
//! - **Console** - Unified console writer abstraction

pub mod console;
pub mod serial;
pub mod vga;

pub use console::WRITER;
pub use serial::SerialPort;
pub use vga::{Color, ColorCode};
