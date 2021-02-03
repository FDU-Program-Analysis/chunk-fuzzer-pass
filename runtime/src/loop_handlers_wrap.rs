use super::*;
use crate::{loop_handlers::ObjectStack};
// use angora_common::{config, tag::TagSeg};
use lazy_static::lazy_static;
use std::{sync::Mutex};
use std::ffi::CStr;
use libc::c_char;

// Lazy static doesn't have reference count and won't call drop after the program finish.
// So, we should call drop manually.. see ***_fini.
lazy_static! {
    static ref OS: Mutex<Option<ObjectStack>> = Mutex::new(Some(ObjectStack::new()));
}

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
    let mut osl = OS.lock().unwrap();
    if let Some(ref mut os) = *osl {
        os.get_load_label(addr, size);
    }
}

#[no_mangle]
pub extern "C" fn __chunk_push_new_obj(
    _a: bool,
    _b: u32,
    _c: u32,
) {
    panic!("Forbid calling __chunk_push_new_obj directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_push_new_obj(
    is_loop: bool,
    loop_cnt: u32,
    loop_hash: u32,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    _l2: DfsanLabel,
) {
    if is_loop && loop_cnt != 0 {
        return;
    }
    let mut osl = OS.lock().unwrap();
    if let Some(ref mut os) = *osl {
        os.new_obj(is_loop, loop_hash);
    } 
}

#[no_mangle]
pub extern "C" fn __chunk_dump_each_iter(
    _a: u32,
) {
    panic!("Forbid calling __chunk_dump_each_iter directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_dump_each_iter(
    loop_cnt: u32,
    _l0: DfsanLabel,
) {
    if loop_cnt == 0 {
        return;
    }
    else {
        println!("[LOG]: Loop iter: {} #[LOG]",loop_cnt);
        let mut osl = OS.lock().unwrap();
        if let Some(ref mut os) = *osl {
            os.dump_cur_iter(loop_cnt);
        } 
    } 
}

#[no_mangle]
pub extern "C" fn __chunk_pop_obj(
    _a: u32,
)  -> bool {
    panic!("Forbid calling __chunk_pop_obj directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_pop_obj(
    loop_hash: u32,
    _l0: DfsanLabel,
) -> bool {
    let mut osl = OS.lock().unwrap();
    if let Some(ref mut os) = *osl {
        os.pop_obj(loop_hash);
        true
    } else {
        panic!("POP ERROR!");
    }
}

#[no_mangle]
pub extern "C" fn __chunk_object_stack_fini() {
    let mut osl = OS.lock().unwrap();
    *osl = None;
}

#[no_mangle]
pub extern "C" fn __chunk_set_input_file_name(name: *const c_char){
    let mut osl = OS.lock().unwrap();
    if let Some(ref mut os) = *osl {
        let c_str = unsafe { CStr::from_ptr(name)};
        let str_: &str = c_str.to_str().unwrap();
        let v: Vec<&str> = str_.split('/').collect();
        let str_buf: &mut String = &mut String::new();
        for i in v {
            str_buf.push_str(i);
            str_buf.push_str("_");
        }
        str_buf.push_str(".json");
        os.set_input_file_name(str_buf);
    } 
}

#[no_mangle]
pub extern "C" fn __chunk_trace_cmp_tt(
    _a: u32,
    _b: u32,
    _c: u64,
    _d: u64,
    _e: u32,
) {
    panic!("Forbid calling __chunk_trace_cmp_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_cmp_tt(
    size: u32,
    op: u32,
    arg1: u64,
    arg2: u64,
    condition: u32,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    l2: DfsanLabel,
    l3: DfsanLabel,
    _l4: DfsanLabel,
) {
    println!("__chunk_trace_cmp_tt : {0},{1},{2},{3},{4} ",size,op,arg1,arg2,condition);
}

#[no_mangle]
pub extern "C" fn __chunk_trace_switch_tt(
    _a: u32,
    _b: u64,
    _c: u32,
    _d: *mut u64
) {
    panic!("Forbid calling __chunk_trace_switch_tt directly");
}


#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_switch_tt(
    size: u32,
    condition: u64,
    num: u32,
    args: *mut u64,
    _l0: DfsanLabel,
    l1: DfsanLabel,
    _l2: DfsanLabel,
    _l3: DfsanLabel,
) {
    println!("__chunk_trace_switch_tt : {},{},{},{:?} ",size,condition,num,args);
}

/*
#[no_mangle]
pub extern "C" fn __chunk_trace_fn_tt(
    _a: u32,
    _b: u32,
    _c: u32,
    _d: *mut i8,
    _e: *mut i8
) {
    panic!("Forbid calling __chunk_trace_fn_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_fn_tt(
    cmpid: u32,
    context: u32,
    size: u32,
    parg1: *mut i8,
    parg2: *mut i8,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    _l2: DfsanLabel,
    _l3: DfsanLabel,
    _l4: DfsanLabel,
) {
    
}

#[no_mangle]
pub extern "C" fn __chunk_trace_exploit_val_tt(
    _a: u32,
    _b: u32,
    _c: u32,
    _d: u32,
    _e: u64
) {
    panic!("Forbid calling __chunk_trace_exploit_val_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_exploit_val_tt(
    cmpid: u32,
    context: u32,
    size: u32,
    op: u32,
    val: u64,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    _l2: DfsanLabel,
    _l3: DfsanLabel,
    l4: DfsanLabel,
) {
    
}
*/