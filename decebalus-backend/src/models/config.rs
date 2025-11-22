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


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_new_config_is_empty() {
        let cfg = Config::new();
        assert!(cfg.settings.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_default_config_is_empty() {
        let cfg: Config = Default::default();
        assert!(cfg.settings.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_set_and_get_value() {
        let mut cfg = Config::new();
        cfg.set("username".to_string(), json!("shadowmonk"));

        assert_eq!(
            cfg.get("username"),
            Some(&json!("shadowmonk"))
        );
    }

    #[test]
    fn test_get_missing_key_returns_none() {
        let cfg = Config::new();
        assert!(cfg.get("missing").is_none());
    }

    #[test]
    fn test_setting_multiple_values() {
        let mut cfg = Config::new();
        cfg.set("user".to_string(), json!("shadowmonk"));
        cfg.set("age".to_string(), json!(31));

        let obj = cfg.settings.as_object().unwrap();
        assert_eq!(obj.len(), 2);
        assert_eq!(cfg.get("user"), Some(&json!("shadowmonk")));
        assert_eq!(cfg.get("age"), Some(&json!(31)));
    }

    #[test]
    fn test_set_overwrites_old_value() {
        let mut cfg = Config::new();
        cfg.set("theme".to_string(), json!("light"));
        cfg.set("theme".to_string(), json!("dark"));

        assert_eq!(cfg.get("theme"), Some(&json!("dark")));
    }
}
