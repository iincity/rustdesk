//! Test-only native RustDesk Publishing Host for the WSL tunnel harness.

#[derive(Clone)]
struct HeadlessConnectionManager;

impl librustdesk::ui_cm_interface::InvokeUiCM for HeadlessConnectionManager {
    fn add_connection(&self, _client: &librustdesk::ui_cm_interface::Client) {}
    fn remove_connection(&self, _id: i32, _close: bool) {}
    fn new_message(&self, _id: i32, _text: String) {}
    fn change_theme(&self, _dark: String) {}
    fn change_language(&self) {}
    fn show_elevation(&self, _show: bool) {}
    fn update_voice_call_state(&self, _client: &librustdesk::ui_cm_interface::Client) {}
    fn file_transfer_log(&self, _action: &str, _log: &str) {}
}

fn main() {
    if let Ok(app_name) = std::env::var("NEXUS_E2E_APP_NAME") {
        if !app_name.trim().is_empty() {
            *hbb_common::config::APP_NAME.write().unwrap() = app_name;
        }
    }
    hbb_common::init_log(false, "nexus-e2e-host");
    if std::env::args()
        .skip(1)
        .any(|arg| arg == "--cm" || arg == "--cm-no-ui")
    {
        println!("NEXUS_E2E_HEADLESS_CM_READY");
        librustdesk::ui_cm_interface::start_ipc(librustdesk::ui_cm_interface::ConnectionManager {
            ui_handler: HeadlessConnectionManager,
        });
        return;
    }
    let rendezvous = std::env::var("NEXUS_E2E_RENDEZVOUS_SERVER")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            eprintln!("NEXUS_E2E_RENDEZVOUS_SERVER is required");
            std::process::exit(2);
        });
    hbb_common::config::Config::set_option("custom-rendezvous-server".into(), rendezvous);
    // KCP coverage deliberately disables only the direct TCP listener; the
    // existing rendezvous UDP/KCP path remains unchanged and must carry the
    // PortForward session on its own.
    let direct_server = if std::env::var("NEXUS_E2E_DISABLE_DIRECT_SERVER").as_deref() == Ok("1") {
        "N"
    } else {
        "Y"
    };
    hbb_common::config::Config::set_option("direct-server".into(), direct_server.into());
    if let Ok(key) = std::env::var("NEXUS_E2E_RENDEZVOUS_KEY") {
        hbb_common::config::Config::set_option("key".into(), key);
    }
    hbb_common::config::Config::set_key_confirmed(true);
    if let Ok(password) = std::env::var("NEXUS_E2E_LEGACY_PASSWORD") {
        if password.is_empty() || !hbb_common::config::Config::set_permanent_password(&password) {
            eprintln!("NEXUS_E2E_LEGACY_PASSWORD must set a non-empty Host password");
            std::process::exit(2);
        }
    }
    if let Some(seed_hex) = std::env::var("NEXUS_E2E_TUNNEL_SIGNING_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        let Ok(seed_bytes) = hex::decode(seed_hex) else {
            eprintln!("NEXUS_E2E_TUNNEL_SIGNING_KEY must be a 32-byte hex seed");
            std::process::exit(2);
        };
        let Some(seed) = hbb_common::sodiumoxide::crypto::sign::Seed::from_slice(&seed_bytes)
        else {
            eprintln!("NEXUS_E2E_TUNNEL_SIGNING_KEY must be a 32-byte hex seed");
            std::process::exit(2);
        };
        let (public_key, _) = hbb_common::sodiumoxide::crypto::sign::keypair_from_seed(&seed);
        std::env::set_var("NEXUS_TUNNEL_SIGNING_KEY_ID", "default");
        std::env::set_var(
            "NEXUS_TUNNEL_SIGNING_PUBLIC_KEY_HEX",
            hex::encode(public_key),
        );
    }
    let id = hbb_common::config::Config::get_id();
    let key_pair = hbb_common::config::Config::get_key_pair();
    println!("NEXUS_E2E_HOST_ID={id}");
    println!("NEXUS_E2E_HOST_PUBLIC_KEY_HEX={}", hex::encode(key_pair.1));
    use std::io::Write;
    let _ = std::io::stdout().flush();
    if std::env::var("NEXUS_E2E_PRINT_IDENTITY").as_deref() == Ok("1") {
        std::thread::sleep(std::time::Duration::from_millis(100));
        return;
    }
    if let Ok(control_plane_url) = std::env::var("NEXUS_E2E_AGENT_CONTROL_PLANE_URL") {
        let device_uid = std::env::var("NEXUS_E2E_AGENT_DEVICE_UID").unwrap_or_else(|_| {
            eprintln!("NEXUS_E2E_AGENT_DEVICE_UID is required with Agent control plane");
            std::process::exit(2);
        });
        // Let the native Host own its single Tokio/runtime lifecycle.  Starting
        // a second test runtime here would be replaced by `start_server` and
        // make the optional Agent Socket observe an unbound device identity.
        hbb_common::config::Config::set_option("nexus-device-uid".into(), device_uid);
        hbb_common::config::Config::set_option("nexus-control-plane-url".into(), control_plane_url);
        hbb_common::config::Config::set_option(
            "nexus-presence-gateway".into(),
            "127.0.0.1:9".into(),
        );
        hbb_common::config::Config::set_option("nexus-presence-bind".into(), "127.0.0.1:0".into());
        if let Ok(path) = std::env::var("NEXUS_E2E_AGENT_READY_FILE") {
            std::thread::spawn(move || loop {
                if librustdesk::nexus::status_snapshot().is_some_and(|status| {
                    status.agent_health == librustdesk::nexus::AgentHealthState::Ready
                }) {
                    let _ = std::fs::write(path, "ready\n");
                    println!("NEXUS_E2E_AGENT_READY");
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            });
        }
        if let (Ok(path), Ok(version)) = (
            std::env::var("NEXUS_E2E_DESIRED_STATE_READY_FILE"),
            std::env::var("NEXUS_E2E_DESIRED_STATE_VERSION").and_then(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| std::env::VarError::NotPresent)
            }),
        ) {
            std::thread::spawn(move || loop {
                if librustdesk::nexus::status_snapshot().is_some_and(|status| {
                    status.tunnel.desired_version.map(|value| value.0) == Some(version)
                        && status.tunnel.applied_version.map(|value| value.0) == Some(version)
                }) {
                    let _ = std::fs::write(path, "applied\n");
                    println!("NEXUS_E2E_DESIRED_STATE_APPLIED");
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            });
        }
    }
    librustdesk::start_server(true, false);
}
