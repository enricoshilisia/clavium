mod bridge;
mod commands;
mod state;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .setup(|app| {
            bridge::spawn(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_exists,
            commands::vault_create,
            commands::vault_unlock,
            commands::vault_lock,
            commands::vault_is_unlocked,
            commands::vault_export_sealed,
            commands::vault_list_records,
            commands::vault_add_record,
            commands::vault_update_record,
            commands::vault_delete_record,
            commands::generate_password,
            commands::totp_code,
            bridge::bridge_generate_pairing_code,
            bridge::bridge_list_paired,
            bridge::bridge_revoke_paired,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
