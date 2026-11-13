/// Every `#[tauri::command]` in `generate_handler!` (src/lib.rs). Declaring
/// them here makes Tauri generate an `allow-<command>` permission for each and
/// deny any command a window's capability does not grant (issue #20). A unit
/// test keeps this list in sync with the handler.
const COMMANDS: &[&str] = &[
    "app_info",
    "vault_status",
    "list_vaults",
    "select_vault",
    "check_new_vault",
    "add_existing_vault",
    "update_vault",
    "forget_vault",
    "set_hide_vault_names",
    "delete_vault",
    "show_in_explorer",
    "inspect_keyfile",
    "create_vault",
    "unlock",
    "reload_vault",
    "lock",
    "list_items",
    "get_item",
    "create_item",
    "update_item",
    "delete_item",
    "purge_history",
    "set_favorite",
    "copy_field",
    "reveal_password",
    "totp_code",
    "generate_password",
    "export_backup",
    "inspect_backup",
    "preview_import",
    "apply_import",
    "preview_csv",
    "import_csv",
    "shred_csv",
    "detect_browsers",
    "list_folders",
    "create_folder",
    "rename_folder",
    "delete_folder",
    "show_spotlight",
    "hide_spotlight",
    "open_main_window",
    "add_attachment",
    "save_attachment",
    "delete_attachment",
    "duress_status",
    "set_duress_password",
    "clear_duress_password",
    "bridge_state",
    "bridge_start_pairing",
    "bridge_cancel_pairing",
    "bridge_revoke",
    "bridge_approve_save",
    "bridge_reject_save",
    "browser_support_status",
    "set_browser_support",
];

fn main() {
    // Tauri only embeds its app manifest into binaries. We embed our own into
    // every target instead, so `cargo test` executables get it too.
    let windows = tauri_build::WindowsAttributes::new_without_app_manifest();
    let attrs = tauri_build::Attributes::new()
        .windows_attributes(windows)
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    tauri_build::try_build(attrs).expect("failed to run tauri-build");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rerun-if-changed=windows-app-manifest.xml");
        embed_resource::compile_for_everything("windows-app-manifest.rc", embed_resource::NONE)
            .manifest_required()
            .expect("failed to embed Windows app manifest");
    }
}
