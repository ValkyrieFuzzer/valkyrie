use crate::cond_stmt::CondStmt;
use angora_common::cond_stmt_base::CondStmtBase;
use std::cmp::{Ord, Ordering, PartialOrd};

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct CondId {
    pub cmpid: u32,
    pub context: u32,
    pub order: u32,
    pub op: u32,
}

impl PartialOrd<CondId> for CondId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.cmpid != other.cmpid {
            return Some(self.cmpid.cmp(&other.cmpid));
        } else if self.context != other.context {
            return Some(self.context.cmp(&other.context));
        } else if self.order != other.order {
            return Some(self.order.cmp(&other.order));
        } else if self.op != other.op {
            return Some(self.op.cmp(&other.op));
        } else {
            Some(Ordering::Equal)
        }
    }
}
impl Ord for CondId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl CondId {
    pub fn new(cmpid: u32, context: u32, order: u32, op: u32) -> Self {
        Self {
            cmpid,
            context,
            order,
            op,
        }
    }
    pub fn from_cond_base(cond: &CondStmtBase) -> Self {
        Self::new(cond.cmpid, cond.context, cond.order, cond.op)
    }
    pub fn from_cond(cond: &CondStmt) -> Self {
        Self::from_cond_base(&cond.base)
    }
}
