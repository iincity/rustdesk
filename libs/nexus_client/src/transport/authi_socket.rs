//! Pure Authi Socket.IO/Engine.IO wire helpers.
//!
//! WebSocket I/O remains a RustDesk adapter because `WsFramedStream` belongs to
//! `hbb_common`. This module owns only the protocol envelope and JSON DTOs.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentDispatch {
    pub execution_id: String,
    pub dispatch_token: String,
    pub tenant_id: String,
    pub provider: String,
    pub model: Option<String>,
    pub prompt: String,
    pub timeout_ms: u64,
    #[serde(default)]
    pub tunnel_access: bool,
}

#[derive(Debug, Deserialize)]
pub struct AgentRpcRequest {
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCancellation {
    pub execution_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentExecutionStart<'a> {
    pub dispatch_token: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentExecutionFinish<'a> {
    pub dispatch_token: &'a str,
    pub status: &'a str,
    pub exit_code: Option<i32>,
    pub error_code: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRuntimeMetrics {
    pub queue_depth: u8,
}

/// Parse a Socket.IO event frame (`42["event", payload]`).
pub fn parse_socket_io_event(frame: &str) -> Option<(Option<String>, String, serde_json::Value)> {
    let body = frame.strip_prefix("42")?;
    let array_at = body.find('[')?;
    let ack_id = (!body[..array_at].is_empty()).then(|| body[..array_at].to_owned());
    let values: Vec<serde_json::Value> = serde_json::from_str(&body[array_at..]).ok()?;
    let event = values.first()?.as_str()?.to_owned();
    Some((
        ack_id,
        event,
        values.get(1).cloned().unwrap_or(serde_json::Value::Null),
    ))
}

pub fn encode_socket_io_event(event: &str, payload: &serde_json::Value) -> String {
    format!("42{}", serde_json::json!([event, payload]))
}

pub fn encode_socket_io_ack(ack_id: &str, accepted: bool) -> String {
    format!(
        "43{ack_id}{}",
        serde_json::json!([{ "accepted": accepted }])
    )
}

/// Build the only permitted machine-scoped websocket endpoint.
pub fn agent_socket_endpoint(control_plane_url: &str) -> Result<String, String> {
    let authority = control_plane_url
        .strip_prefix("https://")
        .and_then(|value| value.split(['/', '?', '#']).next())
        .filter(|value| {
            !value.is_empty() && !value.chars().any(char::is_whitespace) && !value.contains('@')
        })
        .ok_or_else(|| "Nexus control-plane URL must use HTTPS".to_string())?;
    Ok(format!(
        "wss://{authority}/v1/updates/?EIO=4&transport=websocket"
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        agent_socket_endpoint, encode_socket_io_ack, encode_socket_io_event, parse_socket_io_event,
    };

    #[test]
    fn endpoint_requires_https_and_preserves_only_the_socket_route() {
        assert_eq!(
            agent_socket_endpoint("https://control.example/ignored?old=value").unwrap(),
            "wss://control.example/v1/updates/?EIO=4&transport=websocket"
        );
        assert!(agent_socket_endpoint("http://control.example").is_err());
        assert!(agent_socket_endpoint("not a url").is_err());
    }

    #[test]
    fn event_parser_and_ack_encoder_preserve_the_ack_boundary() {
        let (ack, event, payload) =
            parse_socket_io_event("421[\"rpc-request\",{\"executionId\":\"exec-1\"}]").unwrap();
        assert_eq!(ack.as_deref(), Some("1"));
        assert_eq!(event, "rpc-request");
        assert_eq!(payload["executionId"], "exec-1");
        assert_eq!(
            encode_socket_io_event("rpc-register", &serde_json::json!({"method":"m"})),
            "42[\"rpc-register\",{\"method\":\"m\"}]"
        );
        assert_eq!(encode_socket_io_ack("1", true), "431[{\"accepted\":true}]");
    }
}
