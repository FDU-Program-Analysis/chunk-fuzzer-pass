// use super::*;
use angora_common::tag::TagSeg;
// use std::collections::HashMap;

// Loop & Function labels. 
#[derive(Debug)]
pub struct ObjectLabels {
    is_loop: bool,
    cur_iter: Option<Vec<TagSeg>>,
    sum: Vec<TagSeg>,
}


impl ObjectLabels {
    pub fn new(is_loop: bool) -> Self {
        let cur_iter = if is_loop {
            Some(vec![])
        } else {
            None
        };
        Self {
            is_loop,
            cur_iter,
            sum: vec![],
        }
    }
    pub fn merge_cur_iter() -> bool {
        //TODO
        false
    }
}

// stack, pop, push
#[derive(Debug)]
pub struct ObjectStack {
    objs: Vec<ObjectLabels>,
}

impl ObjectStack {
    pub fn new() -> Self {
        let mut objs = vec![];
        objs.push(ObjectLabels::new(false)); //for func:main
        Self { objs }
    }
    pub fn new_obj(
        &mut self,
        is_loop: bool,
    ) {
        println!("enter new_obj"); 
        self.objs.push(ObjectLabels::new(is_loop));
    }
    pub fn dump_all(
        &mut self,
    ) {
        println!("OS: {:?}", self);
    }

}


/*
pub extern "C" fn __load_get_label(
    _a: *const i8,
    _b: usize,
    _c: u32,
) {
    panic!("Forbid calling __loop_get_label directly");
}

// 还需要一个参数，表示当前load涉及到的loop层次序列
pub extern "C" fn __dfsw___load_get_label>(
    addr: *const i8, 
    size: usize,
    cnt: u32,
) 
{
    if cnt 
        return;
    // let curObj = 
    let lb = unsafe { dfsan_read_label(addr, size) };
    let tag = tag_set_wrap::tag_set_find
    if lb {

    } else {

    }

}

pub extern "C" fn __dfsw___func_get_label()->Vec<TagSeg> {

}

// 在exiting edge和backedge之后把当前loop的label清理掉。
// function的flush是不是也要写在这里呢？
pub extern "C" fn __label_set_flush() {}
*/