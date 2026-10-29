//! PEM 落盘/读取。与 center/gwlinkd 一致：先写临时文件、设权限，再原子 rename。

use std::path::Path;

/// 原子写入 PEM，并按 `mode` 设权限（unix）。
pub fn write_pem(path: &Path, content: &str, mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    let tmp = tmp_path(path);
    std::fs::write(&tmp, content)
        .map_err(|err| format!("failed to write {}: {err}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
            .map_err(|err| format!("failed to chmod {}: {err}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|err| format!("failed to persist {}: {err}", path.display()))
}

pub fn read_pem(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|err| format!("failed to read {}: {err}", path.display()))
}

fn tmp_path(path: &Path) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "pem".to_string());
    name.push_str(&format!(".tmp.{}", std::process::id()));
    path.with_file_name(name)
}
