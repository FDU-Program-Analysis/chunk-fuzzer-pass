use super::*;
use angora_common::{tag::*};
// use itertools::Itertools;
use lazy_static::lazy_static;
use crate::{tag_set_wrap};
use std::{fs::File, io::prelude::*, cmp::*, sync::Mutex, time::*};

const STACK_MAX: usize = 100000;

lazy_static! {
    static ref LC: Mutex<Option<Logger>> = Mutex::new(Some(Logger::new()));
}

// Loop & Function labels. 
#[derive(Debug, Clone)]
pub struct ObjectLabels {
    is_loop: bool,
    hash: u32,
    cur_iter: Option<Vec<TaintSeg>>,
    // cur_iter_num: usize, 
    sum: Vec<TaintSeg>,//每次迭代单独记，用迭代次数做索引
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
            // cur_iter_num: 0,
            sum: vec![],
        }
    }
}

#[derive(Debug)]
pub struct ObjectStack {
    objs: Vec<ObjectLabels>,
    cur_id: usize,
    file_name: String,
}

impl ObjectStack {
    pub fn new() -> Self {
        let mut objs = Vec::with_capacity(STACK_MAX);
        objs.push(ObjectLabels::new(false, 0)); //ROOT
        Self { 
        objs ,
        cur_id: 0,
        file_name: String::new(),
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

    // SegTag-> TaintTag ,minimize
    pub fn seg_tag_2_taint_tag(
        lb: u64,
        list : &mut Vec<TagSeg>, 
    )-> Vec<TaintSeg> {
        list.sort_by(|a, b| {
            match a.begin.cmp(&b.begin) {
                Ordering::Equal => b.end.cmp(&a.end),
                other => other,
            }
        });
        let mut cur_begin = 0;
        let mut cur_end = 0;
        let mut new_list = vec![];
        for i in list {
            //new tag
            if cur_begin == cur_end {
                cur_begin = i.begin;
                cur_end = i.end;
            }
            else {
                // push current tag into new_list
                if i.begin > cur_end {
                    new_list.push(TaintSeg{
                        lb,
                        begin: cur_begin, 
                        end: cur_end,
                        son: None,
                    });
                    cur_begin = i.begin;
                    cur_end = i.end;
                } 
                else {
                    cur_end = max(i.end, cur_end);
                }
            }
        }
        if cur_begin != cur_end {
            new_list.push(TaintSeg{
                lb,
                begin: cur_begin, 
                end: cur_end,
                son: None,
            });
        }
        new_list
    }

    // [0,1],[1,2]-->[0,2]
    pub fn minimize_list(
        list : &mut Vec<TaintSeg>, 
    ) {
        list.sort_by(|a, b| {
            match a.begin.cmp(&b.begin) {
                Ordering::Equal => b.end.cmp(&a.end),
                other => other,
            }
        });
        let mut cur_lb = 0u64;
        let mut cur_begin = 0;
        let mut cur_end = 0;
        let mut cur_son = vec![];
        let mut new_list = vec![];
        for i in list.clone() {
            // first TS
            if cur_begin == cur_end {
                cur_lb = i.lb;
                cur_begin = i.begin;
                cur_end = i.end;
                cur_son.push(i);
            }
            else {
                // 断开了
                if i.begin > cur_end {
                    if cur_lb == 0 {
                        cur_lb = hash_combine(&cur_son);
                    }
                    new_list.push(TaintSeg{
                        lb: cur_lb,
                        begin: cur_begin,
                        end: cur_end,
                        son: if cur_son.len() <= 1 {
                                if cur_son.len() == 1 {
                                    cur_son[0].son.clone()
                                }
                                else {
                                    None
                                }
                            }
                            else {
                                Some(cur_son.clone())
                            },
                    });
                    cur_lb = i.lb;
                    cur_begin = i.begin;
                    cur_end = i.end;
                    cur_son.clear();
                    cur_son.push(i);
                }
                else {
                    if i.end > cur_end {
                        cur_lb = 0;
                        cur_end = i.end;
                        cur_son.push(i);
                    }
                }
            }
        }
        if cur_begin != cur_end {
            if cur_lb == 0 {
                cur_lb = hash_combine(&cur_son);
            }
            new_list.push(TaintSeg{
                lb: cur_lb,
                begin: cur_begin, 
                end: cur_end,
                son: if cur_son.len() <= 1 {
                        if cur_son.len() == 1 {
                            cur_son[0].son.clone()
                        }
                        else {
                            None
                        }
                    }
                    else {
                        Some(cur_son.clone())
                    },
            });
        }
        list.clear();
        list.append(&mut new_list);
    }


    pub fn access_check(
        lb: u64,
    ) -> bool {
        let mut lcl = LC.lock().unwrap();
        if let Some(ref mut lc) = *lcl {
            lc.save_tag(lb)
        }
        else {
            false
        } 
        
    }
/*
    pub fn insert_constraints(
        &mut self,
        list : &mut Vec<TaintSeg>,
    ) {
        list.sort_by(|a, b| a.begin.cmp(&b.begin));
        list.dedup();
        self.objs[self.cur_id].constraints.append(list);
        self.objs[self.cur_id].constraints.dedup();
    }
*/

    // 单次load不判断连续和互斥，只在pop和迭代的时候判断
    pub fn get_load_label(
        &mut self,
        lb: u32,
    ) {
        
        if !loop_handlers::ObjectStack::access_check(lb as u64) {
            return;
        }
        let mut set_list = tag_set_wrap::tag_set_find(lb as usize);

        // if set_list.len() > 0 {
        //     println!("prelist: {:?}", set_list);
        // }
        
        let mut list = loop_handlers::ObjectStack::seg_tag_2_taint_tag(lb as u64, &mut set_list);

        // if list.len() > 0 {
        //     println!("afterlist:{:?}", list);
        // }

        loop_handlers::ObjectStack::minimize_list(&mut list);
        // if list.len() > 0 {
        //     println!("load: {:?}", list);
        // }
        self.insert_labels(&mut list);
        return;
    }

    
    pub fn insert_labels(
        &mut self,
        list :&mut Vec<TaintSeg>,
    ) {
        if self.objs[self.cur_id].is_loop {
            if self.objs[self.cur_id].cur_iter.is_none() {
                panic!("[ERR]: Loop object doesn't have cur_iter");
            }
            else {
                let tmp_iter = self.objs[self.cur_id].cur_iter.as_mut().unwrap();
                for i in list.clone() {
                    if tmp_iter.contains(&i) {
                        continue;
                    }
                    else {
                        tmp_iter.push(i);
                    }
                }
            }
        }
        else {
            for i in list.clone() {
                if self.objs[self.cur_id].sum.contains(&i) {
                    continue;
                }
                else {
                    self.objs[self.cur_id].sum.push(i);
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
        let tmp_iter = self.objs[self.cur_id].cur_iter.as_ref().unwrap().clone();
        // let index = self.objs[self.cur_id].cur_iter_num - 1;
        // self.objs[self.cur_id].sum.insert(index, tmp_iter.to_vec());
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
        _loop_cnt: u32,
    ) {
        if self.objs[self.cur_id].is_loop {
            if self.objs[self.cur_id].cur_iter.is_some() {
                let mut tmp_iter = self.objs[self.cur_id].cur_iter.as_mut().unwrap();
                loop_handlers::ObjectStack::minimize_list(&mut tmp_iter);
                // self.objs[self.cur_id].cur_iter_num = loop_cnt as usize;
                self.insert_iter_into_sum();
                self.objs[self.cur_id].cur_iter.as_mut().unwrap().clear();

                // if self.objs[self.cur_id].sum.len() > 0{
                //     println!("dump_cur_iter: {:?}",self.objs[self.cur_id].sum);
                // }

            }
            else {
                panic!("[ERR]: Loop with wrong structure!! #[ERR]");
            }
        }
        else {
            panic!("[ERR]: Function doesn't have iteration!! #[ERR]");
        }

    }

    //退出循环、函数返回后，将当前栈顶pop，minimize, 插入上一层
    //若hash不匹配说明栈不平衡，出错了
    pub fn pop_obj(
        &mut self,
        hash:u32,
    ) {
        let top = self.objs.pop();
        if top.is_some() {
            let top_obj = top.unwrap();

            // if top_obj.sum.len() > 0 {
            //     println!("pop obj: {:?}", top_obj.sum);
            // }
            
            if top_obj.hash != hash {
                panic!("[ERR] :pop error! incorrect Hash {} #[ERR]", top_obj.hash);
            }
            else {
                let mut list = top_obj.sum;
                self.cur_id -= 1;
                // let index = self.objs[self.cur_id].cur_iter_num;
                loop_handlers::ObjectStack::minimize_list(&mut list);
                self.insert_labels(&mut list);
            }
        } else {
            panic!("[ERR] :STACK EMPTY! #[ERR]");
        }
    }



    pub fn output_format(
        s: &mut String,
        ttsg: &TaintSeg,
        depth: usize,
        is_last: bool,
    ){
        let blank = "  ".repeat(depth);
        let blank2 = "  ".repeat(depth+1);
        let start = "start";
        let end = "end";
        // let field = "type";
        let str_son = "son";
        s.push_str(&format!("{}\"{:016X}\":\n", blank, ttsg.lb));
        s.push_str(&format!("{}{{\n",blank));
        //need check lb
        s.push_str(&format!("{}\"{}\": {},\n",blank2, start, ttsg.begin)); //    "start": 0,
        if ttsg.son.is_none() {
            s.push_str(&format!("{}\"{}\": {}\n",blank2, end, ttsg.end));
            if is_last {
                s.push_str(&format!("{}}}\n",blank));
            }
            else {
                s.push_str(&format!("{}}},\n",blank));
            }
            return;
        }
        s.push_str(&format!("{}\"{}\": {},\n",blank2, end, ttsg.end));     //    "end": 8,
        let ttsg_sons = ttsg.son.as_ref().unwrap();
        s.push_str(&format!("{}\"{}\": {{\n",blank2, str_son)); 
        for i in 0 .. ttsg_sons.len() {
        // for (&i_sum, &i_son) in &label.sum.iter().zip(&label.son.iter()) {
            if i == ttsg_sons.len() - 1 {
                loop_handlers::ObjectStack::output_format(s, &ttsg_sons[i], depth+1, true);
            }
            else {
                loop_handlers::ObjectStack::output_format(s, &ttsg_sons[i], depth+1, false);
            }
            // s.push_str(&format!("{}}},\n",blank));
        }
        s.push_str(&format!("{}}}\n",blank2));
        if is_last {
            s.push_str(&format!("{}}}\n",blank));
        } 
        else {
            s.push_str(&format!("{}}},\n",blank));
        }
    }

    pub fn set_input_file_name(
        &mut self,
        input_name: &mut String,
    ){
        // *input_name = input_name.replace(" ", "_");
        // *input_name = input_name.replace(".", "__");
        // input_name.push_str(".json");
        self.file_name = input_name.to_string();
    }

    pub fn fini(
        &mut self,
    ) {
        let mut s = String::new();
        loop_handlers::ObjectStack::minimize_list(&mut self.objs[self.cur_id].sum);
        s.push_str(&format!("{{\n"));
        for i in &self.objs[self.cur_id].sum {
            if &i == &self.objs[self.cur_id].sum.last().unwrap() {
                loop_handlers::ObjectStack::output_format(&mut s, &i, 0, true);
            }
            else {
                loop_handlers::ObjectStack::output_format(&mut s, &i, 0, true);
            }
        }
        s.push_str(&format!("}}\n"));
        if self.file_name.len() == 0 {
            let timestamp = {
                let start = SystemTime::now();
                let since_the_epoch = start
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");
                let ms = since_the_epoch.as_secs() as i64 * 1000i64 + (since_the_epoch.subsec_nanos() as f64 / 1_000_000.0) as i64;
                ms
            };
            self.file_name.push_str("logfile_");
            self.file_name.push_str(&timestamp.to_string());
            self.file_name.push_str(".json");
        }
        let mut fd = File::create(&self.file_name).expect("Unable to create log file");
        fd.write_all(s.as_bytes()).expect("Unable to write file");
    }
}

impl Drop for ObjectStack {
    fn drop(&mut self) {
        self.fini();
    }
}

// print_type_of(&xxx);
// fn print_type_of<T>(_: &T) {
//     println!("{}", std::any::type_name::<T>())
// }


pub fn hash_combine(
    ts: &Vec<TaintSeg>
) -> u64 {
    let mut seed = 0;
    if ts.len() == 1 {
        seed = ts[0].lb
    }
    else {
        for b in  ts {
            seed ^=
                b.lb ^ 0x9E3779B97F4A7C15u64 ^ (seed << 6) ^ (seed >> 2);
        }
    }
    seed
}
