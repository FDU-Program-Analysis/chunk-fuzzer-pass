use super::*;
use crate::tag_set_wrap;


#[no_mangle]
pub extern "C" fn __chunk_get_dump_label(
    _a: *const i8,
    _b: usize,
) {
    panic!("Forbid calling __chunk_get_dump_label directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_get_dump_label(
    addr: *const i8, 
    size: usize,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
) {
    println!("enter __chunk_get_dump_label");
    let lb = unsafe { dfsan_read_label(addr, size) };
    tag_set_wrap::__angora_tag_set_show(lb as usize);
}