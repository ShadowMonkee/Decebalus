use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum HostStatus {
    Up,
    Down,
    Unknown,
}

impl std::fmt::Display for HostStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HostStatus::Up => write!(f, "Host Status Up"),
            HostStatus::Down => write!(f, "Host Status Down"),
            HostStatus::Unknown => write!(f, "Host Status Unknown"),
        }
    }
}
