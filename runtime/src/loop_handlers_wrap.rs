use super::*;
use crate::{loop_handlers::ObjectStack,tag_set_wrap};
use angora_common::{tag::*, cond_stmt_base::*, defs};
use lazy_static::lazy_static;
use std::{slice, sync::Mutex, ffi::CStr};
use libc::c_char;

// Lazy static doesn't have reference count and won't call drop after the program finish.
// So, we should call drop manually.. see ***_fini.
lazy_static! {
    static ref OS: Mutex<Option<ObjectStack>> = Mutex::new(Some(ObjectStack::new()));
    static ref LC: Mutex<Option<Logger>> = Mutex::new(Some(Logger::new()));
}

#[no_mangle]
pub extern "C" fn __chunk_get_load_label(
    _a: *const i8,
    _b: usize,
) {
    panic!("Forbid calling __chunk_get_load_label directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_get_load_label(
    addr: *const i8, 
    size: usize,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
) {
    let mut osl = OS.lock().unwrap();
    if let Some(ref mut os) = *osl {
        let arglen = if size == 0 {
            unsafe { libc::strlen(addr) as usize }
        } else {
            size
        };
        let lb = unsafe { dfsan_read_label(addr, arglen) };
        if lb <= 0 {
            return;
        }
        os.get_load_label(addr, size);
    }
}

#[no_mangle]
pub extern "C" fn __chunk_push_new_obj(
    _a: u8,
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
    _f: u8,
    _g: u8,
    _h: u8,
) {
    panic!("Forbid calling __chunk_trace_cmp_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_cmp_tt(
    size: u32,
    op: u32,
    arg1: u64,
    arg2: u64,
    _condition: u32,
    is_loop: u8,
    is_cnst1: u8,
    is_cnst2: u8,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    l2: DfsanLabel,
    l3: DfsanLabel,
    _l4: DfsanLabel,
    _l5: DfsanLabel,
    _l6: DfsanLabel,
    _l7: DfsanLabel,
) {
    let lb1 = l2;
    let lb2 = l3;
    if lb1 == 0 && lb2 == 0 {
        return;
    }
    infer_shape(lb1, size);
    infer_shape(lb2, size);

    if is_loop == 1 {
        /*
        let mut osl = OS.lock().unwrap();
        if let Some(ref mut os) = *osl {
            // let lb_payload = os.get_length_payload(op, size, lb1, lb2);
            // log_length();
            // lb1和lb2都taint的情况还需要记cond
        }
        */
        println!("Maybe Length");
        return;
    }

    let op = infer_eq_sign(op, lb1, lb2);
    if op == 32 || op == 33 {
        if lb1 != 0 && lb2 == 0 && is_cnst2 == 1 {
            //log enum
            let vec8 = arg2.to_le_bytes().to_vec();
            log_enum(size, lb1 as u64, vec8);
            return;
        }
        else if lb1 == 0 && lb2 != 0 && is_cnst1 == 1 {
            let vec8 = arg1.to_le_bytes().to_vec();
            log_enum(size, lb2 as u64, vec8);
            return;
        }
        else if lb1 != 0 && lb2 != 0 {
            //maybe checksum
            //检查find label的vec长度超过size
        }
    }
    log_cond(op, size, lb1 as u64, lb2 as u64, ChunkField::Constraint);
}

#[no_mangle]
pub extern "C" fn __chunk_trace_switch_tt(
    _a: u32,
    _b: u64,
    _c: u32,
    _d: *mut u64,
    _e: u8
) {
    panic!("Forbid calling __chunk_trace_switch_tt directly");
}


#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_switch_tt(
    size: u32,
    _condition: u64,
    num: u32,
    args: *mut u64,
    is_loop: u8,
    _l0: DfsanLabel,
    l1: DfsanLabel,
    _l2: DfsanLabel,
    _l3: DfsanLabel,
    _l4: DfsanLabel,
) {
    let lb = l1;
    if lb == 0 {
        return;
    }
    infer_shape(lb, size);

    // let mut op = defs::COND_ICMP_EQ_OP;
    let sw_args = unsafe { slice::from_raw_parts(args, num as usize) }.to_vec();

    for arg in sw_args {
        let vec8 = unsafe { slice::from_raw_parts(arg as *const u8, size as usize) }.to_vec();
        log_enum(size, lb as u64, vec8.clone());
    }
}


#[no_mangle]
pub extern "C" fn __chunk_trace_cmpfn_tt(
    _a: *mut i8,
    _b: *mut i8,
    _c: u32,
    _d: u8,
    _e: u8,
) {
    panic!("Forbid calling __chunk_trace_cmpfn_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_cmpfn_tt(
    parg1: *const c_char,
    parg2: *const c_char,
    size: u32,
    _is_cnst1: u8,
    _is_cnst2: u8,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    _l2: DfsanLabel,
    _l3: DfsanLabel,
    _l4: DfsanLabel,
) {
    let (arglen1, arglen2) = if size == 0 {
        unsafe { (libc::strlen(parg1) as usize, libc::strlen(parg2) as usize) }
    } else {
        (size as usize, size as usize)
    };

    let lb1 = unsafe { dfsan_read_label(parg1, arglen1) } as u64;
    let lb2 = unsafe { dfsan_read_label(parg2, arglen2) } as u64;

    if lb1 == 0 && lb2 == 0 {
        return;
    }

    let arg1 = unsafe { slice::from_raw_parts(parg1 as *mut u8, arglen1) }.to_vec();
    let arg2 = unsafe { slice::from_raw_parts(parg2 as *mut u8, arglen2) }.to_vec();

    if lb1 > 0  && lb2 > 0 {
        log_cond(arglen1 as u32, defs::COND_FN_OP, lb1, lb2, ChunkField::Constraint); // op need check
    }
    else if lb1 > 0 {
        log_enum(arglen2 as u32, lb1, arg2);
    }else if lb2 > 0 {
        log_enum(arglen1 as u32, lb2, arg1);
    }
}



#[no_mangle]
pub extern "C" fn __chunk_trace_offsfn_tt(
    _a: u32,
    _b: u32,
    _c: u8,
) {
    panic!("Forbid calling __chunk_trace_offsfn_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_offsfn_tt(
    index: i32,
    op: u32,
    is_cnst_idx: bool,
    l0: DfsanLabel,
    _l1: DfsanLabel,
    _l2: DfsanLabel,
) {
    // op用来指示相对or绝对 0 文件头 1 当前位置 2 文件尾
    if !is_cnst_idx {
        println!("__chunk_trace_offsfn_tt : <{0},{1}, offset>", l0, op);
    }
}

pub extern "C" fn __chunk_trace_lenfn_tt(
    _a: u32,
    _b: u32,
    _c: u32,
    _d: *mut i8,
    _e: *mut i8
) {
    panic!("Forbid calling __chunk_trace_lenfn_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_lenfn_tt(
    dst: *mut i8,
    len1: u32,
    len2: u32,
    is_cnst_dst: bool,
    is_cnst_len1: bool,
    is_cnst_len2: bool,
    _l0: DfsanLabel,
    l1: DfsanLabel,
    l2: DfsanLabel,
    _l3: DfsanLabel,
    _l4: DfsanLabel,
    _l5: DfsanLabel
) {

}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_offsfn_tt(
    index: i32,
    op: u32,
    is_cnst_idx: bool,
    l0: DfsanLabel,
    _l1: DfsanLabel,
    _l2: DfsanLabel,
    _l3: DfsanLabel
) {
    // op用来指示相对or绝对 0 文件头 1 当前位置 2 文件尾
    if(!is_cnst_idx) {println!("__chunk_trace_offsfn_tt : <{0},{1}, offset>", l0, op);}
}

#[no_mangle]
pub extern "C" fn __chunk_trace_lenfn_tt(
    _a: *mut i8,
    _b: u32,
    _c: u32,
    _d: u8,
    _e: u8,
    _f: u8
) {
    panic!("Forbid calling __chunk_trace_lenfn_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_lenfn_tt(
    dst: *mut i8,
    len1: u32,
    len2: u32,
    is_cnst_dst: bool,
    is_cnst_len1: bool,
    is_cnst_len2: bool,
    _l0: DfsanLabel,
    l1: DfsanLabel,
    l2: DfsanLabel,
    _l3: DfsanLabel,
    _l4: DfsanLabel,
    _l5: DfsanLabel
) {
    let len = if len2 == 0 {
        len1 as usize
    } else {
        (len1*len2) as usize
    };

    let lb = unsafe { dfsan_read_label(dst,len) };
    println!("lenfn_tt : {0},{1},{2},{3}", lb, len1, len2, len);
    println!("cons: {0} {1} {2}", is_cnst_dst,is_cnst_len1,is_cnst_len2);

    if (!is_cnst_dst) && (!is_cnst_len1){
        println!("__chunk_trace_lenfn_tt : <{0},{1},len>", lb, l1);
    }

    if len2!=0 && (!is_cnst_dst) && (!is_cnst_len2) {
        println!("__chunk_trace_lenfn_tt : <{0},{1},len>", lb, l2);
    }
    
fn infer_eq_sign(op: u32, lb1: u32, lb2: u32) -> u32 {
    if op == defs::COND_ICMP_EQ_OP
        && ((lb1 > 0 && tag_set_wrap::tag_set_get_sign(lb1 as usize))
            || (lb2 > 0 && tag_set_wrap::tag_set_get_sign(lb2 as usize)))
    {
        return op | defs::COND_SIGN_MASK;
    }
    op
}

fn infer_shape(lb: u32, size: u32) {
    if lb > 0 {
        tag_set_wrap::__angora_tag_set_infer_shape_in_math_op(lb, size);
    }
}

#[inline]
fn log_cond(
    size: u32,
    op: u32,
    lb1: u64,
    lb2: u64,
    field : ChunkField,
) {
    let field = Some(field);
    let cond = CondStmtBase {
        op,
        size,
        lb1,
        lb2,
        field,
    };
    let mut lcl = LC.lock().expect("Could not lock LC.");
    if let Some(ref mut lc) = *lcl {
        lc.save(cond);
    }
}

fn log_enum(
    size: u32,
    lb: u64,
    enums: Vec<u8>
) {
    // 在hashmap里查找lb，把magic_byte插入到candidates里
    if enums.len() != size as usize{
        println!("size error");
        return;
    }
    let mut lcl = LC.lock().expect("Could not lock LC.");
    if let Some(ref mut lc) = *lcl {
        lc.save_enums(lb, enums);
    }
}