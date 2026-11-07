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
        .run(tauri::generate_context!())
        .expect("error while running shush");
}
