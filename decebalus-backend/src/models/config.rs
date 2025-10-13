use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Config {
    pub settings: serde_json::Value,
}

impl Config {
    pub fn new() -> Self {
        Self {
            settings: serde_json::json!({}),
        }
    }
    
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.settings.get(key)
    }
    
    pub fn set(&mut self, key: String, value: serde_json::Value) {
        if let Some(obj) = self.settings.as_object_mut() {
            obj.insert(key, value);
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}