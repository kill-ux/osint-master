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
fn flatten_json_to_kv(value: &serde_json::Value, prefix: &str, out: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.to_string()
                } else {
                    format!("{}_{}", prefix, k)
                };
                flatten_json_to_kv(v, &key, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let key = format!("{}_{}", prefix, i);
                flatten_json_to_kv(v, &key, out);
            }
        }
        serde_json::Value::String(s) => {
            out.push((prefix.to_string(), s.clone()));
        }
        serde_json::Value::Number(n) => {
            out.push((prefix.to_string(), n.to_string()));
        }
        serde_json::Value::Bool(b) => {
            out.push((prefix.to_string(), b.to_string()));
        }
        serde_json::Value::Null => {
            out.push((prefix.to_string(), "null".to_string()));
        }
    }
}

/// Saves a serializable report to a file.
/// 
/// The format is determined by the file extension. `.json` will result in a JSON file,
/// while other extensions will result in a flattened key-value text format.
/// 
/// # Arguments
/// * `path` - The file path to save the report to.
/// * `data` - The serializable data to save.
/// 
/// # Returns
/// * `Result<()>` - Ok if successful, Error otherwise.
pub async fn save_report<T: Serialize>(path: &str, data: &T) -> Result<()> {
    let is_json = Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    let res = if is_json {
        serde_json::to_string_pretty(data)?
    } else {
        let value = serde_json::to_value(data)?;

        let mut entries = Vec::new();
        flatten_json_to_kv(&value, "", &mut entries);

        entries
            .into_iter()
            .map(|(key, val)| format!("{}: {}", key.to_uppercase(), val))
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