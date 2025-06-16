use chrono::Local;
use fern::{
    Dispatch,
    colors::{Color, ColoredLevelConfig},
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
        .level(LevelFilter::Info)
        .chain(fern::log_file(log_file)?)
        .chain(io::stdout())
        .apply()?;
    Ok(())
}
