use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DisplayStatus {
    pub status: String,
    pub last_update: String,
}

impl DisplayStatus {
    pub fn new() -> Self {
        Self {
            status: "idle".to_string(),
            last_update: "never".to_string(),
        }
    }
    
    pub fn update(&mut self, status: String) {
        self.status = status;
        self.last_update = chrono::Utc::now().to_rfc3339();
    }
}

impl Default for DisplayStatus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;

    #[test]
    fn new_initializes_correctly() {
        let ds = DisplayStatus::new();

        assert_eq!(ds.status, "idle");
        assert_eq!(ds.last_update, "never");
    }

    #[test]
    fn update_changes_status_and_timestamp() {
        let mut ds = DisplayStatus::new();

        let old_update = ds.last_update.clone();

        ds.update("running".into());

        assert_eq!(ds.status, "running");
        assert!(ds.last_update != old_update);

        // timestamp should be valid RFC 3339
        assert!(DateTime::parse_from_rfc3339(&ds.last_update).is_ok());
    }

    #[test]
    fn update_multiple_times() {
        let mut ds = DisplayStatus::new();

        ds.update("running".into());
        let first_update = ds.last_update.clone();

        std::thread::sleep(std::time::Duration::from_millis(5));

        ds.update("finished".into());
        let second_update = ds.last_update.clone();

        assert_eq!(ds.status, "finished");
        assert!(second_update > first_update);
    }

    #[test]
    fn default_matches_new() {
        let d1 = DisplayStatus::new();
        let d2 = DisplayStatus::default();

        assert_eq!(d1.status, d2.status);
        assert_eq!(d1.last_update, d2.last_update);
    }


}
