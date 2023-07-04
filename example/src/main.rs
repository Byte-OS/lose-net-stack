// remove std lib
#![no_std]
#![no_main]
#![feature(naked_functions)]
#![feature(asm_const)]
#![feature(ip_in_core)]

use log::LevelFilter;

extern crate alloc;
extern crate opensbi_rt;
#[macro_use]
extern crate log;

mod dns;
mod net;
mod virtio_impls;

/// rust 入口函数
///
/// 进行操作系统的初始化，
#[no_mangle]
pub extern "C" fn main(_hart_id: usize, _device_tree_addr: usize) {
    log::set_max_level(LevelFilter::Debug);

    net::init();
}
