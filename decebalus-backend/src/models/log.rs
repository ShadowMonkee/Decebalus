use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Log {
    pub id: String,
    pub created_at: String,
    pub severity: String,
    pub service: String,
    pub module: Option<String>,
    pub job_id: Option<String>,
    pub content: String,
}

impl Log {
    pub fn new(id: String, created_at: String, severity: String, service: String, module: Option<String>,job_id: Option<String>, content: String) -> Self {
        Self {
            id,
            created_at,
            severity,
            service,
            module,
            job_id,
            content
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn new_initializes_correctly() {
        let log = Log::new(
            "id123".into(),
            "2025-11-20T12:00:00Z".into(),
            "INFO".into(),
            "scanner".into(),
            Some("network".into()),
            Some("job42".into()),
            "Scan completed".into(),
        );

        assert_eq!(log.id, "id123");
        assert_eq!(log.created_at, "2025-11-20T12:00:00Z");
        assert_eq!(log.severity, "INFO");
        assert_eq!(log.service, "scanner");
        assert_eq!(log.module.unwrap(), "network");
        assert_eq!(log.job_id.unwrap(), "job42");
        assert_eq!(log.content, "Scan completed");
    }

    #[test]
    fn optional_fields_can_be_none() {
        let log = Log::new(
            "id123".into(),
            "2025-11-20T12:00:00Z".into(),
            "WARN".into(),
            "database".into(),
            None,
            None,
            "Something happened".into(),
        );

        assert!(log.module.is_none());
        assert!(log.job_id.is_none());
    }

    #[test]
    fn log_can_serialize_and_deserialize() {
        let log = Log::new(
            "id123".into(),
            "2025-11-20T12:00:00Z".into(),
            "ERROR".into(),
            "api".into(),
            Some("auth".into()),
            None,
            "Unauthorized".into(),
        );

        let json = serde_json::to_string(&log).unwrap();
        let deserialized: Log = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, log.id);
        assert_eq!(deserialized.service, "api");
        assert_eq!(deserialized.severity, "ERROR");
        assert_eq!(deserialized.module.unwrap(), "auth");
        assert!(deserialized.job_id.is_none());
    }


}
