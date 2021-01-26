use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd, Debug, Clone, Copy, Hash)]
#[repr(C)] 
pub struct TagSeg {
    pub sign: bool,
    pub begin: u32,
    pub end: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd, Debug, Clone, Copy, Hash)]
pub enum ChunkField {
    Id,
    Length,
    Checksum,
    Index,
    Other,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd, Debug, Clone, Copy, Hash)]
#[repr(C)] 
pub struct TaintSeg {
    pub begin: u32,
    pub end: u32,
    pub field : ChunkField,
}


// impl TagSeg {
//     pub fn slice_from<'a>(&self, v: &'a [u8]) -> &'a [u8] {
//         &v[(self.begin as usize)..(self.end as usize)]
//     }

//     pub fn slice_from_mut<'a>(&self, v: &'a mut [u8]) -> &'a mut [u8] {
//         &mut v[(self.begin as usize)..(self.end as usize)]
//     }
// }
