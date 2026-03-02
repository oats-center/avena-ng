use serde_json::Value;

pub const TELEMETRY_SCHEMA_VERSION: u8 = 1;

#[must_use]
pub fn new_run_id() -> String {
    format!(
        "run-{}-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    )
}

#[must_use]
pub fn subject_for_ns3_payload(run_id: &str, payload: &Value) -> String {
    if let Some(subject) = payload.get("subject").and_then(Value::as_str) {
        if subject.starts_with("avena.v1.") {
            return subject.to_string();
        }
    }

    let suffix = payload
        .get("type")
        .and_then(Value::as_str)
        .map(sanitize_subject_segment)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "event".to_string());

    format!("avena.v1.{run_id}.ns3.{suffix}")
}

fn sanitize_subject_segment(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_run_id_is_non_empty_and_cli_safe() {
        let run_id = new_run_id();
        assert!(!run_id.is_empty());
        assert!(!run_id.contains(char::is_whitespace));
        assert!(
            run_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "run_id contains unexpected characters: {run_id}"
        );
    }

    #[test]
    fn subject_defaults_to_ns3_event_with_type_suffix() {
        let payload = serde_json::json!({"type":"realtime"});
        let subject = subject_for_ns3_payload("run123", &payload);
        assert_eq!(subject, "avena.v1.run123.ns3.realtime");
    }

    #[test]
    fn subject_sanitizes_type_field() {
        let payload = serde_json::json!({"type":"assoc-complete"});
        let subject = subject_for_ns3_payload("run123", &payload);
        assert_eq!(subject, "avena.v1.run123.ns3.assoc_complete");
    }

    #[test]
    fn subject_uses_payload_subject_when_present() {
        let payload = serde_json::json!({"subject":"avena.v1.custom.ns3.l2"});
        let subject = subject_for_ns3_payload("run123", &payload);
        assert_eq!(subject, "avena.v1.custom.ns3.l2");
    }

    #[test]
    fn subject_falls_back_when_payload_subject_invalid() {
        let payload = serde_json::json!({"subject":"not-valid","type":"l2"});
        let subject = subject_for_ns3_payload("run123", &payload);
        assert_eq!(subject, "avena.v1.run123.ns3.l2");
    }
}
