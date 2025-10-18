use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Port {
    pub number: u16,
    pub protocol: String,
    pub status: String,
}