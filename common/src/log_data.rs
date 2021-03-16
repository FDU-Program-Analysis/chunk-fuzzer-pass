use crate::{cond_stmt_base::CondStmtBase};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LogData {
    pub cond_list: Vec<CondStmtBase>,
    pub tags: HashMap<u64, bool>,
    pub enums: HashMap<u64, Vec<Vec<u8>>>, //key: lb, value: candidates
    pub linear_constraint: Vec<u32>,
}

impl LogData {
    pub fn new() -> Self {
        Self {
            cond_list: vec![],
            tags: HashMap::new(),
            enums: HashMap::new(),
            linear_constraint: vec![],
        }
    }
}
