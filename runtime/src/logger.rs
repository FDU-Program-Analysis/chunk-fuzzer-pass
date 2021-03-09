use bincode::{deserialize_from, serialize_into};
use std::{collections::HashMap, env, fs::File, io::prelude::*, path::Path};

// use crate::{len_label, tag_set_wrap};
use angora_common::{cond_stmt_base::*, config, defs, log_data::LogData};

#[derive(Debug)]
pub struct Logger {
    data: LogData,
    // fd: Option<fs::File>,
    // order_map: HashMap<(u32, u32), u32>,
}

impl Logger {
    pub fn new() -> Self {
        // export ANGORA_TRACK_OUTPUT=track.log
        // let fd = match env::var(defs::TRACK_OUTPUT_VAR) {
        //     Ok(path) => match fs::File::create(&path) {
        //         Ok(f) => Some(f),
        //         Err(_) => None,
        //     },
        //     Err(_) => None,
        // };

        Self {
            data: LogData::new(),
            // fd,
            // order_map: HashMap::new(),
        }
    }

    // pub fn set_file_name(&mut self, json_name: String) {
    //     let mut log_name = &json_name;
    //     log_name.replace("json", "log");
    //     self.file_name = log_name.to_string();
    // }

    pub fn save_tag(&mut self, lb: u64) -> bool {
        if lb > 0 {
            // let tag = tag_set_wrap::tag_set_find(lb as usize);
            if self.data.tags.contains_key(&lb) {
                false
            }
            else {
                self.data.tags.entry(lb).or_insert(true);
                true
            }
        }
        else {
            false
        }

    }

    pub fn save_enums(&mut self, lb: u64, bytes: Vec<u8>) {
        if lb > 0 {
            // let tag = tag_set_wrap::tag_set_find(lb as usize);
            if self.data.enums.contains_key(&lb) {
                let v = self.data.enums.get_mut(&lb).unwrap();
                if !v.contains(&bytes) {
                    v.push(bytes);
                }
            }
            else {
                self.data.enums.insert(lb, vec![bytes]);
            }
            
        }
    }

    /*
    // like the fn in fparser.rs
    pub fn get_order(&mut self, cond: &mut CondStmtBase) -> u32 {
        let order_key = (cond.cmpid, cond.context);
        let order = self.order_map.entry(order_key).or_insert(0);
        if cond.order == 0 {
            // first case in switch
            let order_inc = *order + 1;
            *order = order_inc;
        }
        cond.order += *order;
        *order
    }
    */

    pub fn save(&mut self, cond: CondStmtBase) {
        if cond.lb1 == 0 && cond.lb2 == 0 {
            return;
        }

        self.save_tag(cond.lb1);
        self.save_tag(cond.lb2);

        if !self.data.cond_list.contains(&cond) {
            self.data.cond_list.push(cond);
        }
    }

    pub fn enums_clean(&mut self){
        let mut del = vec![];

        for (key, value) in &self.data.enums {
            if value.len() == 1 {
                let target = key.clone();
                del.push(target);
            }
        }
        
        for key in del {
            &self.data.enums.remove(&key);
        }
    }

    pub fn output_logs(&self, s: &mut String) {
        // output：(lb1，lb2, field, remarks)
        // remarks: Enum's candidate; Constraints's op; offset's absolute/relatively
        for (key,value) in &self.data.enums {
            s.push_str(&format!("({:016X};{:016X};Enum;{};{{",key,0,value.len()));
            for vi in value {
                // let enumi = match String::from_utf8(vi.to_vec()) {
                //     Ok(v) => v,
                //     Err(e) => panic!("invalid utf-8 sequence: {}",e),
                // };
                s.push_str(&format!("{:02X?};",vi));
            }
            s.push_str(&format!("}})\n"));
        }
        for i in &self.data.cond_list {
            if i.field != ChunkField::Constraint {
                s.push_str(&format!("({:016X};{:016X};{:?};{})\n", i.lb1, i.lb2, i.field, i.op));
            }
        }
    }

    fn fini(&self) {
        // if let Some(fd) = &self.fd {
        let mut fd = File::create("track.log").expect("Unable to create log file");
        let mut s = String::new();
        self.output_logs(&mut s); 
        fd.write_all(s.as_bytes()).expect("Unable to write file");
            // let mut writer = io::BufWriter::new(fd);
            // serialize_into(&mut writer, &self.data).expect("Could not serialize data.");
        // }
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        self.fini();
    }
}
/*
pub fn get_log_data(path: &Path) -> io::Result<LogData> {
    let f = fs::File::open(path)?;
    if f.metadata().unwrap().len() == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "Could not find any interesting constraint!, Please make sure taint tracking works or running program correctly."));
    }
    let mut reader = io::BufReader::new(f);
    match deserialize_from::<&mut io::BufReader<fs::File>, LogData>(&mut reader) {
        Ok(v) => Ok(v),
        Err(_) => Err(io::Error::new(io::ErrorKind::Other, "bincode parse error!")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
*/