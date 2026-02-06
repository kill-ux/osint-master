use anyhow::Result;

pub async fn run_username_lookup(name: String, _output: Option<String>) -> Result<()> {
    println!("Searching Username: {}", name);
    Ok(())
}
