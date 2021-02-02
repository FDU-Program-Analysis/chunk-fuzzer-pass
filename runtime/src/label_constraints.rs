use angora_common::{cond_stmt_base::CondStmtBase};
use std::{collections::HashMap};

/*
pub struct constraint {
    Vec<CondStmtBase>,
    ChunkField,
}*/

#[derive(Debug)]
pub struct LabelConstraint {
    hmp: HashMap<u32,bool>,
    // hmp: HashMap<u32, Vec<CondStmtBase>>,
}

impl LabelConstraint{
    pub fn new() -> Self {
        Self {
            hmp: HashMap::new(),
        }
    }

    pub fn insert_lb (
        &mut self,
        lb: u32,
    ) -> bool {
        if self.hmp.contains_key(&lb) {
            false
        }
        else {
            self.hmp.entry(lb).or_insert(true);
            true
        }
    }
    /*
    pub fn insert_constraints(
        cnstr: CondStmtBase
    ) {
        //TODO
    }*/

}