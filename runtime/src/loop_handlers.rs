use super::*;
use angora_common::tag::TagSeg;
use crate::{tag_set_wrap};
use std::{cmp};
// use std::collections::HashMap;

const STACK_MAX: usize = 100000;

// Loop & Function labels. 
#[derive(Debug)]
pub struct ObjectLabels {
    is_loop: bool,
    hash: u32,
    continuity: bool,
    non_overlap: bool,
    cur_iter: Option<Vec<TagSeg>>,
    sum: Vec<TagSeg>,
}


impl ObjectLabels {
    pub fn new(
        is_loop: bool,
        hash: u32,
    ) -> Self {
        let cur_iter = if is_loop {
            Some(vec![])
        } else {
            None
        };
        Self {
            is_loop,
            hash,
            cur_iter,
            continuity: true,
            non_overlap: true,
            sum: vec![],
        }
    }
}

// stack, pop, push
#[derive(Debug)]
pub struct ObjectStack {
    objs: Vec<ObjectLabels>,
    cur_id: usize,
}

impl ObjectStack {
    pub fn new() -> Self {
        let mut objs = Vec::with_capacity(STACK_MAX);
        objs.push(ObjectLabels::new(false, 0)); //ROOT
        Self { 
        objs ,
        cur_id: 0,
        }
    }

    #[inline(always)]
    pub fn new_obj(
        &mut self,
        is_loop: bool,
        hash: u32,
    ){
        let len = self.objs.len();
        if len < STACK_MAX {
            self.objs.push(ObjectLabels::new(is_loop, hash));
            self.cur_id += 1;
            println!("[LOG]: is_loop: {} ,hash : {:x}, cur_id: {} #[LOG]", is_loop, hash, self.cur_id);
            return;
        }
        else {
            panic!("[ERR]: more than {} objs.. #[ERR]", STACK_MAX);
        }
    }

    pub fn get_num_objs(&self) -> usize {
        self.objs.len()
    }

    pub fn get_top_index(&self) -> usize {
        return self.get_num_objs() - 1;
    }

    // 将多个标签的offset整合，如[0,1],[1,2]-->[0,2],不区分sign,全记成true
    // TODO: return (continuity: bool, non_overlap: bool,)
    pub fn minimize_list(
        list : &mut Vec<TagSeg>, 
    ) {
        list.sort_by(|a, b| a.begin.cmp(&b.begin));
        let mut cur_begin = 0;
        let mut cur_end = 0;
        let mut new_list = vec![];
        for i in list.clone() {
            //new tag
            if cur_begin == cur_end {
                cur_begin = i.begin;
                cur_end = i.end;
            }
            else {
                // push current tag into new_list
                if i.begin > cur_end {
                    new_list.push(TagSeg{
                        sign: true, 
                        begin: cur_begin, 
                        end: cur_end
                    });
                    cur_begin = i.begin;
                    cur_end = i.end;
                } 
                else {
                    cur_end = cmp::max(i.end, cur_end);
                }
            }
        }
        if cur_begin != cur_end {
            new_list.push(TagSeg{
                sign: true, 
                begin: cur_begin, 
                end: cur_end
            });
        }
        list.clear();
        list.append(&mut new_list);
    }

    // 单次load不判断连续和互斥，只在pop和迭代的时候判断
    pub fn get_load_label(
        &mut self,
        addr: *const i8, 
        size: usize,
    ) {
        let arglen = if size == 0 {
            unsafe { libc::strlen(addr) as usize }
        } else {
            size
        };
        let lb = unsafe { dfsan_read_label(addr, arglen) };
        if lb == 0 {
            return;
        }
        let mut list = tag_set_wrap::tag_set_find(lb as usize);

        loop_handlers::ObjectStack::minimize_list(&mut list);
        self.insert_labels(&mut list);
        return;
    }

    
    pub fn insert_labels(
        &mut self,
        list :&mut Vec<TagSeg>,
    ) {
        if self.objs[self.cur_id].is_loop {
            if self.objs[self.cur_id].cur_iter.is_none() {
                panic!("[ERR]: Loop object doesn't have cur_iter");
            }
            else {
                let mut tmp_iter = self.objs[self.cur_id].cur_iter.as_mut().unwrap();
                for i in list {
                    if tmp_iter.contains(i) {
                        continue;
                    }
                    else {
                        tmp_iter.push(*i);
                    }
                }
            }
        }
        else {
            for i in list {
                if self.objs[self.cur_id].sum.contains(i) {
                    // field :length
                    continue;
                }
                else {
                    self.objs[self.cur_id].sum.push(*i);
                }
            }
        }
    }

    pub fn insert_iter_into_sum(
        &mut self,
    ) {
        if self.objs[self.cur_id].cur_iter.is_none() {
            panic!("insert_iter_into_sum but cur_iter is none!");
        }
        let tmp_iter = self.objs[self.cur_id].cur_iter.as_ref().unwrap();
        for i in tmp_iter.clone() {
            if self.objs[self.cur_id].sum.contains(&i) {
                continue;
            }
            else {
                self.objs[self.cur_id].sum.push(i);
            }
        }
    }

    // dump当前迭代所有数据，并把cur_iter的数据整合进sum中
    //  -> (bool, bool) 
    pub fn dump_cur_iter(
        &mut self,
    ) {
        if self.objs[self.cur_id].is_loop {
            if self.objs[self.cur_id].cur_iter.is_some() {
                let mut tmp_iter = self.objs[self.cur_id].cur_iter.as_mut().unwrap();
                loop_handlers::ObjectStack::minimize_list(&mut tmp_iter);
                self.insert_iter_into_sum();
                self.objs[self.cur_id].cur_iter.as_mut().unwrap().clear();
                if self.objs[self.cur_id].sum.len() != 0 {
                    println!("cur obj: {:?}", self.objs[self.cur_id].sum);
                }
            }
            else {
                panic!("[ERR]: Loop with wrong structure!! #[ERR]");
            }
        }
        else {
            panic!("[ERR]: Function doesn't have iteration!! #[ERR]");
        }

    }



    

    /*
    //将list里的label加到self.objs[cur_id].sum里面，并最小化sum
    //不做list的clear
    //satisfy=true：list 与当前sum的内容无重叠、断开
    pub fn summarize(
        &mut self,
        cur_id: usize,
        list : &mut Vec<TagSeg>,
        satisfy: &mut bool,
    ) -> (bool, bool) {
        *satisfy &= self.objs[cur_id].satisfy;
        //TODO 判断无重叠

        self.objs[cur_id].sum.append(list);
        self.minimize(&mut self.objs[cur_id].sum, &mut satisfy);


    }
*/
    //退出循环、函数返回后，将当前栈顶pop，若hash不匹配说明栈不平衡，出错了
    //dump当前栈顶的所有数据
    pub fn pop_obj(
        &mut self,
        hash:u32,
    ) {
        println!("[LOG]:pop obj, {:x} #[LOG]",hash);
        let top = self.objs.pop();
        if top.is_some() {
            let top_obj = top.unwrap();
            if top_obj.hash != hash {
                panic!("[ERR] :pop error! incorrect Hash #[ERR]");
            }
            else {
                let mut list = top_obj.sum;
                self.cur_id -= 1;
                self.insert_labels(&mut list);
                
            }
        } else {
            panic!("[ERR] :STACK EMPTY! #[ERR]");
        }
    }

    //dump OS内所有数据
    pub fn dump_all(
        &mut self,
    ) {
        println!("[LOG] :OS: {:?} #[LOG]", self);
    }
}


// print_type_of(&xxx);
fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}
