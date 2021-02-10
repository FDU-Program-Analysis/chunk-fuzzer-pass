<<<<<<< HEAD
use crate::{cond_stmt_base::CondStmtBase};
=======
use crate::{cond_stmt_base::CondStmtBase, tag::*};
>>>>>>> f729063d75e66deb2986510563048851d1006871
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LogData {
    pub cond_list: Vec<CondStmtBase>,
<<<<<<< HEAD
    pub tags: HashMap<u64, bool>,
    pub enums: HashMap<u64, Vec<Vec<u8>>>, //key: lb, value: candidates
=======
    // pub tags: HashMap<u32, Vec<TagSeg>>,
    pub tags: HashMap<u64, bool>,
    pub magic_bytes: HashMap<usize, (Vec<u8>, Vec<u8>)>,
>>>>>>> f729063d75e66deb2986510563048851d1006871
}

impl LogData {
    pub fn new() -> Self {
        Self {
            cond_list: vec![],
            tags: HashMap::new(),
            enums: HashMap::new(),
        }
    }
}
