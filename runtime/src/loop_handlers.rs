use super::*;
use angora_common::{tag::*};
// use itertools::Itertools;
use crate::{tag_set_wrap};
use std::{collections::HashMap, fs::File, io::prelude::*, cmp, path::Path};
use std::time::{SystemTime, UNIX_EPOCH};

const STACK_MAX: usize = 100000;

// Loop & Function labels. 
#[derive(Debug, Clone)]
pub struct ObjectLabels {
    is_loop: bool,
    hash: u32,
    cur_iter: Option<Vec<TaintSeg>>,
    cur_iter_num: usize, 
    sum: Vec<Vec<TaintSeg>>,//每次迭代单独记，用迭代次数做索引
    // constraints: Vec<TaintSeg>,
    son: Vec<Vec<ObjectLabels>>,
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
            // constraints: vec![],
            son: vec![],
        }
    }
}

#[derive(Debug)]
pub struct ObjectStack {
    objs: Vec<ObjectLabels>,
    cur_id: usize,
    // hit times for every single byte. Key is TaintSeg.begin
    hit: HashMap<u32, u32>,
    file_name: String,
}

impl ObjectStack {
    pub fn new() -> Self {
        let mut objs = Vec::with_capacity(STACK_MAX);
        objs.push(ObjectLabels::new(false, 0)); //ROOT
        Self { 
        objs ,
        cur_id: 0,
        hit: HashMap::new(),
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

    pub fn seg_tag_2_taint_tag(
        list : &mut Vec<TagSeg>, 
    )-> Vec<TaintSeg> {
        let mut ret = vec![];
        for i in list {
            ret.push(TaintSeg{
                begin: i.begin, 
                end: i.end,
                field: ChunkField::Other
            });
        }
        ret
    }

    // [0,1],[1,2]-->[0,2]
    // TODO: return (continuity: bool, non_overlap: bool,)
    pub fn minimize_list(
        list : &mut Vec<TaintSeg>, 
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
                    new_list.push(TaintSeg{
                        begin: cur_begin, 
                        end: cur_end,
                        field: ChunkField::Other
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
            new_list.push(TaintSeg{
                begin: cur_begin, 
                end: cur_end,
                field: ChunkField::Other
            });
        }
        list.clear();
        list.append(&mut new_list);
    }

    pub fn minimize_sum(
        list : &mut Vec<Vec<TaintSeg>>, 
    ) -> Vec<TaintSeg> {
        let mut new_list = vec![];
        for i in list {
            new_list.append(i);
        }
        loop_handlers::ObjectStack::minimize_list(&mut new_list);
        new_list
    }


    pub fn access_time(
        &mut self,
        list : &mut Vec<TaintSeg>,
    ) -> Vec<TaintSeg>{
        // access多次的直接从list里删掉，放到ret里,ret的内容不参与chunk切分，但是是自描述数据
        let mut new_list = vec![];
        let mut ret = vec![];
        for i in list.clone() {
            if self.hit.contains_key(&i.begin) {
                let count = self.hit.entry(i.begin).or_insert(0);
                *count += 1;
                ret.push(i);
            }
            else {
                self.hit.entry(i.begin).or_insert(0);
                new_list.push(i);
            }
        }
        list.clear();
        list.append(&mut new_list);
        loop_handlers::ObjectStack::minimize_list(&mut ret);
        ret
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
        let mut set_list = tag_set_wrap::tag_set_find(lb as usize);
        if set_list.len() > 0 {
            println!("prelist: {:?}", set_list);
        }
        let mut list = loop_handlers::ObjectStack::seg_tag_2_taint_tag(&mut set_list);
        if list.len() > 0 {

        println!("afterlist:{:?}", list);
        }
        // let mut constraints = self.access_time(&mut list);
        // self.insert_constraints(&mut constraints);

        loop_handlers::ObjectStack::minimize_list(&mut list);
        if list.len() > 0 {
            println!("load: {:?}", list);
        }
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
            //function没有迭代，全都插在第0项。
            if self.objs[self.cur_id].sum.len() == 0 {
                self.objs[self.cur_id].sum.insert(0,vec![]);
            }
            for i in list {
                if self.objs[self.cur_id].sum[0].contains(i) {
                    // field :length
                    continue;
                }
                else {
                    self.objs[self.cur_id].sum[0].push(*i);
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
        let index = self.objs[self.cur_id].cur_iter_num - 1;
        self.objs[self.cur_id].sum.insert(index, tmp_iter.to_vec());
        /*
        for i in tmp_iter.clone() {
            if self.objs[self.cur_id].sum.contains(&i) {
                continue;
            }
            else {
                self.objs[self.cur_id].sum.push(i);
            }
        }*/
    }

    // dump当前迭代所有数据，并把cur_iter的数据按照loop_cnt作为索引整合进sum中
    //  -> (bool, bool) 
    pub fn dump_cur_iter(
        &mut self,
        loop_cnt: u32,
    ) {
        if self.objs[self.cur_id].is_loop {
            if self.objs[self.cur_id].cur_iter.is_some() {
                let mut tmp_iter = self.objs[self.cur_id].cur_iter.as_mut().unwrap();
                loop_handlers::ObjectStack::minimize_list(&mut tmp_iter);
                self.objs[self.cur_id].cur_iter_num = loop_cnt as usize;
                self.insert_iter_into_sum();
                self.objs[self.cur_id].cur_iter.as_mut().unwrap().clear();

                if self.objs[self.cur_id].sum.len() > 0{
                println!("dump_cur_iter: {:?}",self.objs[self.cur_id].sum);
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

    //退出循环、函数返回后，将当前栈顶pop，minimize, 插入上一层
    //若hash不匹配说明栈不平衡，出错了
    pub fn pop_obj(
        &mut self,
        hash:u32,
    ) {
        let top = self.objs.pop();
        if top.is_some() {
            let top_obj = top.unwrap();
            if top_obj.sum.len() > 0 {

            println!("pop obj: {:?}", top_obj.sum);
            }
            if top_obj.hash != hash {
                panic!("[ERR] :pop error! incorrect Hash {} #[ERR]", top_obj.hash);
            }
            else {
                let mut list = top_obj.sum.clone();
                self.cur_id -= 1;
                let index = self.objs[self.cur_id].cur_iter_num;
                if self.objs[self.cur_id].son.len() <= index {
                    let mut empty_num = index+1 - self.objs[self.cur_id].son.len();
                    while empty_num != 0 {
                        self.objs[self.cur_id].son.push(vec![]);
                        empty_num -= 1;
                    }
                }
                self.objs[self.cur_id].son[index].push(top_obj);
                // println!("constraints: {:?}", top_obj.constraints);
                /*
                if list.len() == 1 && top_obj.son.len() == 1 && top_obj.son[0].sum.len() == 1 {
                    // let son = top_obj.son;
                    self.objs[self.cur_id].son.push(top_obj.son[0].clone());
                }
                else if list.len() > 0 {
                    self.objs[self.cur_id].son.push(top_obj);
                }
                */
                let mut min_list = loop_handlers::ObjectStack::minimize_sum(&mut list);
                self.insert_labels(&mut min_list);
            }
        } else {
            panic!("[ERR] :STACK EMPTY! #[ERR]");
        }
    }

    pub fn output_format(
        s: &mut String,
        label: &ObjectLabels,
        depth: usize,
        prefix: String,
    ){
        let blank = "  ".repeat(depth);
        let blank2 = "  ".repeat(depth+1);
        let start = "start";
        let end = "end";
        let field = "type";
        let str_son = "son";
        let mut son_flag = false;
        s.push_str(&format!("{}{}:{{\n", blank, prefix));
        if label.sum.len() > 1 {
            son_flag = true;
        }
        if son_flag {
            s.push_str(&format!("{}\"{}\": {{\n",blank, str_son)); 
        }
        for i in 0 .. label.sum.len() {
        // for (&i_sum, &i_son) in &label.sum.iter().zip(&label.son.iter()) {
            let prefix_i = prefix.clone() + &format!("{:02X}", i);
            s.push_str(&format!("{}\"{}\": {{\n",blank, &prefix_i));         //"00": {
            if label.sum[i].len() > 0 {
                for j_sum in &label.sum[i] {
                    s.push_str(&format!("{}\"{}\": {},\n",blank2, start, j_sum.begin)); //    "start": 0,
                    s.push_str(&format!("{}\"{}\": {},\n",blank2, end, j_sum.end));     //    "end": 8,
                    s.push_str(&format!("{}\"{}\": \"{:?}\",\n",blank2, field, j_sum.field)); //"type": Other
                }  
            }
            //print son
            if label.son.len() > i && label.son[i].len() != 0 {
                for j_son in &label.son[i] {
                    if j_son.sum.len() > 0 {
                        loop_handlers::ObjectStack::output_format(s, &j_son, depth+1, prefix_i.clone());
                    }
                }
            }
            s.push_str(&format!("{}}},\n",blank));
        }
        if son_flag {
            s.push_str(&format!("{}}}\n",blank)); 
        }
        /*
        s.push_str(&format!("{}\"son\": {{\n",blank2));
        for i in &label.son {
            loop_handlers::ObjectStack::output_format(s, &i, depth+1);
        }
        s.push_str(&format!("{}}},\n",blank2));
        */
        s.push_str(&format!("{}}},\n",blank));
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
        loop_handlers::ObjectStack::output_format(&mut s, &self.objs[self.cur_id], 0, String::new());
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
fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}
