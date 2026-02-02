use chrono::Local;
use fern::{
    colors::{Color, ColoredLevelConfig},
    Dispatch,
};
use log::LevelFilter;
use std::io;

/// Initialize logging to file and stdout with timestamps and colored levels.
pub fn init_logging(log_file: &str) -> anyhow::Result<()> {
    // configure colors for terminal output
    let colors = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Green)
        .debug(Color::Cyan)
        .trace(Color::BrightBlack);

    // Get log level from RUST_LOG environment variable, default to Info
    let log_level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|level| match level.to_lowercase().as_str() {
            "trace" => Some(LevelFilter::Trace),
            "debug" => Some(LevelFilter::Debug),
            "info" => Some(LevelFilter::Info),
            "warn" => Some(LevelFilter::Warn),
            "error" => Some(LevelFilter::Error),
            _ => None,
        })
        .unwrap_or(LevelFilter::Info);

    Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} - {} - {} - {}",
                Local::now().to_rfc3339(),
                colors.color(record.level()),
                record.target(),
                message
            ))
        })
        .level(log_level)
        .chain(fern::log_file(log_file)?)
        .chain(io::stdout())
        .apply()?;
    Ok(())
}
