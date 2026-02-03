use anyhow::Result;

pub async fn run(name: String, _output: Option<String>) -> Result<()> {
    println!("Searching Username: {}", name);
    Ok(())
}
