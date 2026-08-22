//! Feature-gated public-side Gateway for one signed native PortForward.

fn main() {
    hbb_common::init_log(false, "nexus-gateway");
    let runtime =
        hbb_common::tokio::runtime::Runtime::new().expect("Nexus Gateway runtime unavailable");
    if let Err(error) = runtime.block_on(librustdesk::nexus::run_headless_gateway_from_env()) {
        eprintln!("Nexus Gateway stopped: {error}");
        std::process::exit(2);
    }
}
