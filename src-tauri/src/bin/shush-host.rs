//! `shush-host.exe`: native-messaging relay between a browser extension and
//! the running shush (issue #51). No Tauri, WebView or vault code: it only
//! moves framed bytes, and only to a pipe served by `shush.exe` from its own
//! folder. Message bodies are never logged; stdout carries protocol frames
//! only, so diagnostics go to stderr.

#[cfg(windows)]
fn main() {
    use shush_lib::bridge::relay::{connect_verified, relay};
    use shush_lib::os::pipe::pipe_name;

    let result = (|| -> Result<(), String> {
        let name = pipe_name().map_err(|e| format!("cannot name the pipe: {e}"))?;
        let mut pipe = connect_verified(&name).map_err(|e| e.to_string())?;
        relay(
            &mut std::io::stdin().lock(),
            &mut std::io::stdout().lock(),
            &mut pipe,
        )
        .map_err(|e| format!("relay stopped: {e}"))
    })();
    if let Err(msg) = result {
        eprintln!("shush-host: {msg}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("shush-host is only supported on Windows");
    std::process::exit(1);
}
