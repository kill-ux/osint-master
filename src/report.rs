use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::path::Path;
use tokio::{fs::{create_dir_all, File}, io::AsyncWriteExt};
use tracing::warn;

/// Persist a serializable report to the filesystem in either JSON or a
/// simple `KEY: VALUE` text format depending on the extension of `path`.
///
/// This replaces the repetitive `save_report` implementations found in
/// the various domain/ip/username modules and ensures all callers behave
/// identically when creating parent directories or formatting errors.
pub async fn save_report<T: Serialize>(path: &str, data: &T) -> Result<()> {
    let res = if path.ends_with("json") {
        serde_json::to_string_pretty(data)?
    } else {
        serde_txtrecord::to_txt_records(data)?
            .into_iter()
            .map(|(key, value)| format!("{}: {}", key.to_uppercase(), value))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let path = Path::new(path);
    if let Some(parent) = path.parent()
        && parent.to_str() != Some("")
    {
        warn!("Directory doesn't exist, will be created");
        create_dir_all(parent).await?;
    }

    let mut fd = File::create(path).await?;
    fd.write_all(res.as_bytes()).await?;
    println!(
        "{} {}",
        "Data successfully saved to:".green(),
        path.to_string_lossy()
    );
    Ok(())
}