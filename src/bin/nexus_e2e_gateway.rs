//! Test-only loopback Gateway for the native RustDesk tunnel process harness.

fn main() {
    if let Ok(app_name) = std::env::var("NEXUS_E2E_APP_NAME") {
        if !app_name.trim().is_empty() {
            *hbb_common::config::APP_NAME.write().unwrap() = app_name;
        }
    }
    hbb_common::init_log(false, "nexus-e2e-gateway");
    if std::env::var("NEXUS_E2E_PRINT_IDENTITY").as_deref() == Ok("1") {
        let id = hbb_common::config::Config::get_id();
        let key_pair = hbb_common::config::Config::get_key_pair();
        println!("NEXUS_E2E_GATEWAY_ID={id}");
        println!(
            "NEXUS_E2E_GATEWAY_PUBLIC_KEY_HEX={}",
            hex::encode(key_pair.1)
        );
        // Config persists a newly generated RustDesk key asynchronously. Keep
        // this test-only identity process alive long enough for the next
        // Gateway process to reuse the registered key.
        std::thread::sleep(std::time::Duration::from_millis(100));
        return;
    }
    if let Ok(key) = std::env::var("NEXUS_E2E_RENDEZVOUS_KEY") {
        hbb_common::config::Config::set_option("key".into(), key);
    }
    let runtime =
        hbb_common::tokio::runtime::Runtime::new().expect("Nexus E2E Gateway runtime unavailable");
    let result = if std::env::var("NEXUS_E2E_LEGACY_PORT_FORWARD").as_deref() == Ok("1") {
        runtime.block_on(librustdesk::nexus::run_legacy_port_forward_from_env_for_e2e())
    } else if std::env::var("NEXUS_E2E_REMOTE_SMOKE").as_deref() == Ok("1") {
        runtime.block_on(librustdesk::nexus::run_remote_smoke_from_env_for_e2e())
    } else {
        runtime.block_on(librustdesk::nexus::run_headless_gateway_from_env_for_e2e())
    };
    if let Err(error) = result {
        eprintln!("Nexus E2E Gateway stopped: {error}");
        std::process::exit(2);
    }
}
