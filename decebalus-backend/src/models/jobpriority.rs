use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum JobPriority {
    LOW,
    NORMAL,
    HIGH,
    CRITICAL
}