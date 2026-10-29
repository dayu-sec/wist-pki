//! PEM 落盘/读取。与 center/gwlinkd 一致：先写临时文件、设权限，再原子 rename。
//!
//! 临时文件名带 `pid + 进程内自增序号`：同进程并发写同一路径时不会互相踩，
//! 任何一步失败都会把临时文件清掉（不留 `.tmp.*` 垃圾）。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

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

    if let Err(err) = set_mode(&tmp, mode) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }

    if let Err(err) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("failed to persist {}: {err}", path.display()));
    }
    Ok(())
}

pub fn read_pem(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|err| format!("failed to read {}: {err}", path.display()))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|err| format!("failed to chmod {}: {err}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "pem".to_string());
    name.push_str(&format!(
        ".tmp.{}.{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wist-pki-fs-{}-{name}-{}",
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn creates_missing_parent_directories() {
        let dir = scratch("parents");
        let path = dir.join("a/b/c/ca.pem");
        write_pem(&path, "hello", 0o600).expect("write");
        assert_eq!(fs::read_to_string(&path).expect("read"), "hello");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn applies_the_requested_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("mode");
        fs::create_dir_all(&dir).expect("dir");
        let key = dir.join("ca.key");
        write_pem(&key, "secret", 0o600).expect("write");
        let mode = fs::metadata(&key).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let cert = dir.join("ca.pem");
        write_pem(&cert, "public", 0o644).expect("write");
        let mode = fs::metadata(&cert).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn overwrites_existing_content_atomically() {
        let dir = scratch("overwrite");
        fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("cert.pem");
        write_pem(&path, "first", 0o644).expect("first");
        write_pem(&path, "second", 0o644).expect("second");
        assert_eq!(fs::read_to_string(&path).expect("read"), "second");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn leaves_no_temporary_files_behind() {
        let dir = scratch("tmpclean");
        fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("cert.pem");
        for _ in 0..5 {
            write_pem(&path, "x", 0o644).expect("write");
        }
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .expect("readdir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "leftover tmp files: {leftovers:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_writes_to_one_path_do_not_lose_files() {
        let dir = scratch("concurrent");
        fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("cert.pem");

        let mut handles = Vec::new();
        for index in 0..8 {
            let path = path.clone();
            handles.push(std::thread::spawn(move || {
                write_pem(&path, &format!("content-{index}"), 0o644).expect("write");
            }));
        }
        for handle in handles {
            handle.join().expect("join");
        }

        let final_content = fs::read_to_string(&path).expect("read");
        assert!(final_content.starts_with("content-"));
        let leftovers = fs::read_dir(&dir)
            .expect("readdir")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(leftovers, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_reports_the_path_when_missing() {
        let dir = scratch("missing");
        let path = dir.join("nope.pem");
        let err = read_pem(&path).unwrap_err();
        assert!(err.contains("nope.pem"), "unexpected error: {err}");
    }

    #[test]
    fn read_rejects_non_utf8() {
        let dir = scratch("nonutf8");
        fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("raw.bin");
        fs::write(&path, [0xff, 0xfe, 0x00]).expect("write");
        assert!(read_pem(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
