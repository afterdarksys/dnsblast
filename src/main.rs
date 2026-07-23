use anyhow::{Context, Result};
use clap::Parser;
use dnsblast::{cli::Cli, config::RunConfig, engine, report};

fn main() {
    if let Err(error) = try_main() {
        eprintln!("dnsblast: {error:#}");
        std::process::exit(2);
    }
}

fn try_main() -> Result<()> {
    let cli = Cli::parse();
    let config = RunConfig::from_cli(&cli)?;
    report::validate_output(cli.output, cli.output_file.as_deref())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.workers)
        .enable_all()
        .build()
        .context("failed to initialize async runtime")?;
    let result = runtime.block_on(engine::run(config))?;
    report::emit(&result, cli.output, cli.output_file.as_deref())
}
