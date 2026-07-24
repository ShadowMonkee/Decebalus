use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Service {
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
}