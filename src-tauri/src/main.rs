// Hide the console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    shush_lib::builder()
        // Must be registered first: a second launch (e.g. double-clicking the
        // desktop shortcut again) focuses the running instance instead of
        // starting another process that could write the vault (issue #9).
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            shush_lib::show_main_window(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .build(tauri::generate_context!())
        .expect("error while building shush")
        .run(|_app, event| {
            // Spec §6.3: a copied secret must not outlive the app, whichever
            // path exits it (tray quit, programmatic exit, ...). Clears only if
            // the clipboard still holds shush's content.
            if let tauri::RunEvent::Exit = event {
                shush_lib::os::clipboard::clear_if_ours();
            }
        });
}
