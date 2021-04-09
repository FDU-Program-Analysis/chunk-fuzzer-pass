use super::*;
use angora_common::{tag::*, cond_stmt_base::*};
// use itertools::Itertools;
use lazy_static::lazy_static;
use crate::{tag_set_wrap};
use std::{
    fs::File, 
    io::prelude::*, 
    cmp::*, 
    sync::Mutex, 
    // time::*,
    path:: PathBuf,
};
use std::collections::HashMap;
use rand::Rng;

const STACK_MAX: usize = 100000;

lazy_static! {
    pub static ref LC: Mutex<Option<Logger>> = Mutex::new(Some(Logger::new()));
}

// Loop & Function labels. 
#[derive(Debug, Clone)]
pub struct ObjectLabels {
    is_loop: bool,
    hash: u32,
    cur_iter: Option<Vec<TaintSeg>>,
    cur_iter_num: u32, 
    sum: Vec<TaintSeg>,
    length_candidates: HashMap<u32, u32>,
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
            cur_iter_num: 0,
            sum: vec![],
            length_candidates: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct ObjectStack {
    objs: Vec<ObjectLabels>,
    cur_id: usize,
    fd: Option<File>,
    access_counter: u32,
}

impl ObjectStack {
    pub fn new() -> Self {
        
        let mut objs = Vec::with_capacity(STACK_MAX);
        objs.push(ObjectLabels::new(false, 0)); //ROOT
        Self { 
        objs ,
        cur_id: 0,
        // file_name: String::new(),
        fd: None,
        access_counter: 1,
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
        &mut self,
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
                        cntr: self.access_counter,
                    });
                    cur_begin = i.begin;
                    cur_end = i.end;
                    self.access_counter += 1;
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
                cntr: self.access_counter,
            });
            self.access_counter += 1;
        }
        new_list
    }

    pub fn insert_node(
        ancestor: &mut TaintSeg,
        node: TaintSeg,
    ) {
        if let Some(ref mut son) = ancestor.son {
            for i in 0 .. son.len() {
                match loop_handlers::ObjectStack::seg_relation(&son[i], &node) {
                    SegRelation::Father => {
                        loop_handlers::ObjectStack::insert_node(&mut son[i], node);
                        return;
                    },
                    SegRelation::Same => {
                        son[i].lb = min(son[i].lb, node.lb);
                        if ! node.son.is_none() {
                            let tmp = node.clone().son.unwrap();
                            for son_i in tmp {
                                loop_handlers::ObjectStack::insert_node(&mut son[i], son_i);
                            }
                        }
                        return;
                    },
                    SegRelation::Son => {
                        let mut tmp = son.clone();
                        tmp.push(node);
                        loop_handlers::ObjectStack::construct_tree(&mut tmp);
                        if tmp.len() == 1 {
                            son.clear();
                            son.append(&mut tmp[0].son.clone().unwrap());
                        }
                        return;
                    },
                    SegRelation::RightOverlap => {
                        if loop_handlers::ObjectStack::access_check(son[i].lb as u64, 0) == 0 {
                            son[i].end = node.end;
                            loop_handlers::ObjectStack::insert_node(&mut son[i], node.clone());
                            son[i].lb = hash_combine(son[i].son.as_ref().unwrap());
                        }
                        return;
                    }
                    _ => {},
                } 
            }
            son.push(node); //未排除son之间overlap情况
            son.sort_by(|a, b| {
                match a.begin.cmp(&b.begin) {
                    Ordering::Equal => b.end.cmp(&a.end),
                    other => other,
                }
            });
        }
        else {
            ancestor.son = Some(vec![node]);
        }
    }

    // (TS)a is the subject, for example, return value "Father" means (TS)a is (TS)b's father
    pub fn seg_relation(
        a: &TaintSeg,
        b: &TaintSeg,
    )-> SegRelation {
        if a.begin == b.begin && a.end == b.end {
            SegRelation::Same
        }
        else if a.begin <= b.begin && a.end >= b.end {
            SegRelation::Father
        }
        else if a.begin >= b.begin && a.end <= b.end {
            SegRelation::Son
        }
        else if a.begin == b.end {
            SegRelation::LeftConnect
        }
        else if a.end == b.begin {
            SegRelation::RightConnect
        }
        else if a.begin > b.begin && a.begin < b.end {
            SegRelation::LeftOverlap
        }
        else if a.end > b.begin && a.end < b.end {
            SegRelation::RightOverlap
        }
        else {
            SegRelation::Disjoint
        }
    }

    pub fn erase_lb_wrapper(
        list : &Vec<u64>,
    ) {
        let mut lcl = LC.lock().unwrap();
        if let Some(ref mut lc) = *lcl {
            for i in list {
                lc.erase_lb(*i);
            }
        }
    }
    pub fn handle_overlap (
        list : &mut Vec<TaintSeg>,
    ) {
        if list.len() <= 1 {
            return;
        }
        let mut retain_list = vec![];
        for i in 0 .. list.len() {
            if list[i].cntr == u32::MAX {
                retain_list.push(list[i].clone());
            }
            else if list[i].son.is_some() {
                retain_list.push(list[i].clone());
            };
        }
        for i in 0 .. retain_list.len() {
            if let Some(index) = list.iter().position(|x| *x == retain_list[i]) {
                list.remove(index);
            };
        }
        if list.len() <= 1 {
            list.append(&mut retain_list);
            return;
        }
        let mut overlap_start = usize::MAX;
        let mut overlap_end = usize::MAX;
        let mut erase_lbs = vec![];
        list.sort_by(|a, b| {
            match a.begin.cmp(&b.begin) {
                Ordering::Equal => b.end.cmp(&a.end),
                other => other,
            }
        });
        for i in 0 .. list.len()-1 {
            match loop_handlers::ObjectStack::seg_relation(&list[i], &list[i+1]) {
                SegRelation::RightOverlap => {
                    if overlap_start == usize::MAX {
                        overlap_start = i;
                    }
                    overlap_end = i+1;
                },
                _ => {
                    retain_list.push(list[i].clone());
                    if overlap_start != usize::MAX && overlap_end != usize::MAX {
                        if list[overlap_start].cntr > list[overlap_end].cntr {
                            retain_list.push(list[overlap_start].clone());
                            for i in overlap_start+1 .. overlap_end+1 {
                                erase_lbs.push(list[i].lb);
                            } 
                        }
                        else {
                            retain_list.push(list[overlap_end].clone());
                            for i in overlap_start .. overlap_end {
                                erase_lbs.push(list[i].lb);
                            }
                        }
                        overlap_start = usize::MAX;
                        overlap_end = usize::MAX;
                    }
                }
            };
        }

        if overlap_start == usize::MAX && overlap_end == usize::MAX {
            retain_list.push(list[list.len()-1].clone());
        }
        else {
            if list[overlap_start].cntr > list[overlap_end].cntr {
                retain_list.push(list[overlap_start].clone());
                for i in overlap_start+1 .. overlap_end+1 {
                    erase_lbs.push(list[i].lb);
                } 
            }
            else {
                retain_list.push(list[overlap_end].clone());
                for i in overlap_start .. overlap_end {
                    erase_lbs.push(list[i].lb);
                }
            }
        }
        loop_handlers::ObjectStack::erase_lb_wrapper(&erase_lbs);
        list.clear();
        list.append(&mut retain_list);
        
    }

    pub fn construct_tree(
        mut list : &mut Vec<TaintSeg>,
    ) {
        loop_handlers::ObjectStack::handle_overlap(&mut list);
        if list.len() <= 1 {
            return;
        }
        list.sort_by(|a, b| {
            match a.begin.cmp(&b.begin) {
                Ordering::Equal => b.end.cmp(&a.end),
                other => other,
            }
        });
        // println!("vec to minimize: {:?}", list);
        let mut new_list = vec![];
        let none_ts = TaintSeg{
            lb: 0,
            begin: 0,
            end: 0,
            son: Some(vec![]),
            cntr: u32::MAX,
        };
        let mut cur_ts = none_ts.clone();
        for i in 0 .. list.len() {
            if cur_ts == none_ts {
                cur_ts = list[i].clone();
            }
            else {
                match loop_handlers::ObjectStack::seg_relation(&cur_ts, &list[i]) {
                    SegRelation::Same => {
                        cur_ts.lb = min(cur_ts.lb, list[i].lb);
                        if ! list[i].son.is_none() {
                            let tmp = list[i].clone().son.unwrap();
                            for son_i in tmp {
                                loop_handlers::ObjectStack::insert_node(&mut cur_ts, son_i);
                            }
                        }
                    },
                    SegRelation::Father => {
                        loop_handlers::ObjectStack::insert_node(&mut cur_ts, list[i].clone())
                    },
                    SegRelation::Son => {
                        let prev_ts = cur_ts;
                        cur_ts = list[i].clone();
                        loop_handlers::ObjectStack::insert_node(&mut cur_ts, prev_ts);
                    },
                    SegRelation::RightConnect => {
                        if loop_handlers::ObjectStack::access_check(cur_ts.lb as u64, 0) != 0 {
                            let prev_ts = cur_ts.clone();
                            cur_ts = none_ts.clone();
                            cur_ts.begin = prev_ts.begin;
                            cur_ts.end = list[i].end;
                            if let Some(ref mut son) = cur_ts.son {
                                son.push(prev_ts);
                                son.push(list[i].clone());
                            }
                            else {
                                cur_ts.son = Some(vec![prev_ts, list[i].clone()]);
                            }
                            cur_ts.lb = hash_combine(cur_ts.son.as_ref().unwrap());
                            //cur_ts 和 list[i]为同一层，同为son
                        }
                        else {
                            //合并得到的lb
                            cur_ts.end = list[i].end;
                            if let Some(ref mut son) = cur_ts.son {
                                son.push(list[i].clone());
                                cur_ts.lb = hash_combine(&son);
                            }                            
                        }
                    },
                    SegRelation::RightOverlap => {
                        if cur_ts.son.is_none() && list[i].son.is_none() {
                            //the funtion handle_overlap has filterd out this situation
                            println!("please check function: handle_overlap");
                        }
                        if loop_handlers::ObjectStack::access_check(cur_ts.lb as u64, 0) == 0 {
                            // lb comes from hash_combine
                            cur_ts.end = list[i].end;
                            loop_handlers::ObjectStack::insert_node(&mut cur_ts, list[i].clone());
                            cur_ts.lb = hash_combine(cur_ts.son.as_ref().unwrap());
                        }
                        else if loop_handlers::ObjectStack::access_check(list[i].lb as u64, 0) == 0 {
                            let prev_ts = cur_ts.clone();
                            cur_ts = list[i].clone();
                            cur_ts.begin = prev_ts.begin;
                            loop_handlers::ObjectStack::insert_node(&mut cur_ts, prev_ts);
                            cur_ts.lb = hash_combine(cur_ts.son.as_ref().unwrap());
                        }
                        else {
                        }
                        
                    },
                    SegRelation::Disjoint => {
                        new_list.push(cur_ts);
                        cur_ts = list[i].clone();
                    },
                    _ => {},
                }
            }
        }
        if cur_ts != none_ts {
            new_list.push(cur_ts);
        }
        list.clear();
        list.append(&mut new_list);
    }

    // if size == 0 ,search lb in LC, return 0 if not found
    // if size != 0, save lb in LC, always return 0
    pub fn access_check(
        lb: u64,
        size: u32,
    ) -> u32 {
        let mut lcl = LC.lock().unwrap();
        if let Some(ref mut lc) = *lcl {
            lc.save_tag(lb,size)
        }
        else {
            0
        }
    }

    pub fn maybe_length(
        &mut self,
        lb: u32,
    ) {
        *self.objs[self.cur_id].length_candidates.entry(lb).or_insert(0)+=1;
    }

    pub fn get_load_label(
        &mut self,
        lb: u32,
    ) -> u32 {
        let saved = loop_handlers::ObjectStack::access_check(lb as u64, 0);
        if saved != 0 {
            return saved;
        }
        let mut set_list = tag_set_wrap::tag_set_find(lb as usize);

        // if set_list.len() > 0 {
        //     println!("prelist: {:?}", set_list);
        // }
        
        let mut list = self.seg_tag_2_taint_tag(lb as u64, &mut set_list);

        if list.len() > 1 {
            let mut lcl = LC.lock().unwrap();
            if let Some(ref mut lc) = *lcl {
                lc.save_linear_constraint(lb)
            }
            return 0;
        }
        if list.len() != 0 {
            // println!("load: lb {}, {:?}", lb, list);
            let size = list[0].end - list[0].begin;
            self.insert_labels(&mut list);
            loop_handlers::ObjectStack::access_check(lb as u64, size);
            return size;
        }
        return 0;
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

    // sum <= sum + cur_iter, cur_iter.clear()
    pub fn dump_cur_iter(
        &mut self,
        loop_cnt: u32,
    ) {
        if self.objs[self.cur_id].is_loop {
            if self.objs[self.cur_id].cur_iter.is_some() {
                let mut tmp_iter = self.objs[self.cur_id].cur_iter.as_mut().unwrap();
                loop_handlers::ObjectStack::construct_tree(&mut tmp_iter);
                self.insert_iter_into_sum();
                self.objs[self.cur_id].cur_iter.as_mut().unwrap().clear();
                self.objs[self.cur_id].cur_iter_num = loop_cnt;

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
            
            if hash != 0 && top_obj.hash != hash {
                panic!("[ERR] :pop error! incorrect Hash {} #[ERR]", top_obj.hash);
            }
            else {
                let mut list = top_obj.sum;
                loop_handlers::ObjectStack::construct_tree(&mut list);
                if list.len() == 1 {
                for (key,value) in &top_obj.length_candidates {
                    let size = loop_handlers::ObjectStack::access_check(*key as u64, 0);
                    
                    if size != 0 && *value == top_obj.cur_iter_num {
                        // println!("loop_hash:{}, iter_num:{}, key: {}, value:{}, size: {}", hash, top_obj.cur_iter_num ,*key, *value, size);
                        let cond = CondStmtBase {
                            op: 0,
                            size,
                            lb1: *key as u64,
                            lb2: list[0].lb,
                            field: ChunkField::Length,
                        };
                        let mut lcl = LC.lock().expect("Could not lock LC.");
                        if let Some(ref mut lc) = *lcl {
                            lc.save(cond);
                        }
                    }
                }
                }
                self.cur_id -= 1;
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
        father_begin: u32,
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
        s.push_str(&format!("{}\"{}\": {},\n",blank2, start, ttsg.begin - father_begin)); //    "start": 0,
        if ttsg.son.is_none() {
            s.push_str(&format!("{}\"{}\": {}\n",blank2, end, ttsg.end - father_begin));
            if is_last {
                s.push_str(&format!("{}}}\n",blank));
            }
            else {
                s.push_str(&format!("{}}},\n",blank));
            }
            return;
        }
        s.push_str(&format!("{}\"{}\": {},\n",blank2, end, ttsg.end - father_begin));     //    "end": 8,
        let ttsg_sons = ttsg.son.as_ref().unwrap();
        s.push_str(&format!("{}\"{}\": {{\n",blank2, str_son)); 
        let mut fake_seg = TaintSeg{
            lb: 0,
            begin: 0,
            end: 0,
            son: None,
            cntr: u32::MAX,
        };
        let mut rng = rand::thread_rng();
        for i in 0 .. ttsg_sons.len() {
            if i == 0 {
                if ttsg_sons[0].begin != ttsg.begin {
                    fake_seg.lb = rng.gen_range(0..0x10000000)+0x10000000;
                    fake_seg.begin = ttsg.begin;
                    fake_seg.end = ttsg_sons[0].begin;
                    loop_handlers::ObjectStack::output_format(s, &fake_seg.clone(), depth+1, false, ttsg.begin);
                }
            }
            else if ttsg_sons[i-1].end != ttsg_sons[i].begin {
                fake_seg.lb = rng.gen_range(0..0x10000000)+0x10000000;
                fake_seg.begin = ttsg_sons[i-1].end;
                fake_seg.end = ttsg_sons[i].begin;
                loop_handlers::ObjectStack::output_format(s, &fake_seg.clone(), depth+1, false, ttsg.begin);
            }
            if i == ttsg_sons.len() - 1 {
                if ttsg.end != ttsg_sons[i].end {
                    fake_seg.lb = rng.gen_range(0..0x10000000)+0x10000000;
                    fake_seg.begin = ttsg_sons[ttsg_sons.len() - 1].end;
                    fake_seg.end = ttsg.end;
                    loop_handlers::ObjectStack::output_format(s, &ttsg_sons[i], depth+1, false, ttsg.begin);
                    loop_handlers::ObjectStack::output_format(s, &fake_seg.clone(), depth+1, true, ttsg.begin);
                }
                else {
                    loop_handlers::ObjectStack::output_format(s, &ttsg_sons[i], depth+1, true, ttsg.begin);
                }
            }
            else {
                loop_handlers::ObjectStack::output_format(s, &ttsg_sons[i], depth+1, false, ttsg.begin);
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
        json_name: PathBuf,
    ){
        if self.fd.is_some() {
            return;
        }
        // println!("json_name: {:?}", json_name);
        let json_file = match File::create(json_name) {
            Ok(a) => a,
            Err(e) => {
                panic!("FATAL: Could not create json file: {:?}", e);
            }
        };
        self.fd = Some(json_file);
    }

    fn patch_up(
        &mut self,
    ) {
        let origin_length = self.objs[self.cur_id].sum.len();
        let mut rng = rand::thread_rng();
        for i in 0 .. origin_length - 1 {
            if self.objs[self.cur_id].sum[i].end < self.objs[self.cur_id].sum[i+1].begin {
                let fake_ttsg = TaintSeg{
                    lb: rng.gen_range(0..0x10000000)+0x20000000,
                    begin: self.objs[self.cur_id].sum[i].end,
                    end: self.objs[self.cur_id].sum[i+1].begin,
                    son: None,
                    cntr: u32::MAX,
                };
                self.objs[self.cur_id].sum.push(fake_ttsg);
            }
        }
    }

    pub fn fini(
        &mut self,
    ) {
        // println!("fini: cur_id: {}, objs:{:?}",self.cur_id,self.objs);
        while self.cur_id != 0 {
            self.pop_obj(0);
        }
        //complete vacancies chunk
        if self.objs[self.cur_id].sum.len() > 1 {
            self.patch_up();
        }
        let mut s = String::new();
        loop_handlers::ObjectStack::construct_tree(&mut self.objs[self.cur_id].sum);
        s.push_str(&format!("{{\n"));
        for i in &self.objs[self.cur_id].sum {
            if &i == &self.objs[self.cur_id].sum.last().unwrap() {
                loop_handlers::ObjectStack::output_format(&mut s, &i, 0, true, 0);
            }
            else {
                loop_handlers::ObjectStack::output_format(&mut s, &i, 0, true, 0);
            }
        }
        s.push_str(&format!("}}\n"));

        // if self.file_name.len() == 0 {
        //     let timestamp = {
        //         let start = SystemTime::now();
        //         let since_the_epoch = start
        //             .duration_since(UNIX_EPOCH)
        //             .expect("Time went backwards");
        //         let ms = since_the_epoch.as_secs() as i64 * 1000i64 + (since_the_epoch.subsec_nanos() as f64 / 1_000_000.0) as i64;
        //         ms
        //     };
        //     self.file_name.push_str("logfile_");
        //     self.file_name.push_str(&timestamp.to_string());
        //     self.file_name.push_str(".json");
        // }
        // let mut fd = File::create(&self.file_name).expect("Unable to create log file");
        if self.fd.is_some() {
            self.fd.as_ref().unwrap().write_all(s.as_bytes()).expect("Unable to write file");
        }
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
