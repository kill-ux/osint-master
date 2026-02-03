use anyhow::Result;

pub async fn run_ip_lookup(target: String, _output: Option<String>) -> Result<()> {
    println!("Searching IP: {}", target);
    Ok(())
}
