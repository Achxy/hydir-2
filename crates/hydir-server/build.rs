use std::{env, error::Error, fs, path::Path, process::Command};

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed=HYDIR_SOURCE_REVISION");
    println!("cargo:rerun-if-env-changed=HYDIR_SOURCE_ARCHIVE");
    let output = Path::new(&env::var("OUT_DIR")?).join("source_offer.rs");
    let revision = match env::var("HYDIR_SOURCE_REVISION") {
        Ok(value) => value,
        Err(_) => {
            if env::var_os("HYDIR_SOURCE_ARCHIVE").is_some() {
                return Err("HYDIR_SOURCE_ARCHIVE requires HYDIR_SOURCE_REVISION".into());
            }
            fs::write(
                output,
                "const SOURCE_REVISION: &str = \"\";\nconst SOURCE_ARCHIVE: &[u8] = &[];\n",
            )?;
            return Ok(());
        }
    };
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("HYDIR_SOURCE_REVISION must be a full 40-character Git SHA".into());
    }
    let head = Command::new("git").args(["rev-parse", "HEAD"]).output()?;
    if !head.status.success() || String::from_utf8_lossy(&head.stdout).trim() != revision {
        return Err("source-offer revision does not match checkout HEAD".into());
    }
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .output()?;
    if !dirty.status.success() || !dirty.stdout.is_empty() {
        return Err("source-offer build requires a clean committed checkout".into());
    }
    let archive_path = env::var("HYDIR_SOURCE_ARCHIVE")?;
    let archive_path = fs::canonicalize(archive_path)?;
    let expected_name = format!("hydir-source-{revision}.tar");
    if archive_path.file_name().and_then(|value| value.to_str()) != Some(expected_name.as_str()) {
        return Err("source archive filename does not match build revision".into());
    }
    let archive = fs::read(&archive_path)?;
    if archive.len() > 16 * 1024 * 1024 || archive.len() < 512 {
        return Err("source archive must be a bounded, nonempty tar".into());
    }
    let prefix = format!("hydir-source-{revision}/");
    let tar_name = &archive[..100];
    let tar_name = tar_name.split(|byte| *byte == 0).next().unwrap_or_default();
    if tar_name != prefix.as_bytes() || &archive[257..262] != b"ustar" {
        return Err("source archive root does not match build revision".into());
    }
    println!("cargo:rerun-if-changed={}", archive_path.display());
    fs::write(
        output,
        format!(
            "const SOURCE_REVISION: &str = {revision:?};\nconst SOURCE_ARCHIVE: &[u8] = include_bytes!({:?});\n",
            archive_path.display().to_string()
        ),
    )?;
    Ok(())
}
