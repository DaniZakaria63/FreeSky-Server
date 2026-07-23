use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Initialize logging from `.env` configuration.
///
/// When `DEBUG=true` (or `1`) in `.env` or the environment, enables
/// debug-level logging to **both** stdout and a session log file
/// (`freesky.log`). Otherwise, logs at info level to stdout only.
///
/// The `.env` file is loaded silently — if it doesn't exist, defaults
/// are used (info level, no file output).
pub fn init() -> anyhow::Result<()> {
    // Load .env if present (ignore error if file doesn't exist)
    let _ = dotenvy::dotenv();

    let debug = std::env::var("DEBUG")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_filter(if debug {
            tracing_subscriber::filter::LevelFilter::DEBUG
        } else {
            tracing_subscriber::filter::LevelFilter::INFO
        });

    if debug {
        // Also write debug logs to a session file
        let file_appender = tracing_appender::rolling::never(".", "freesky.log");
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(file_appender)
            .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG);

        tracing_subscriber::registry()
            .with(stdout_layer)
            .with(file_layer)
            .init();
    } else {
        tracing_subscriber::registry().with(stdout_layer).init();
    }

    Ok(())
}
