use console::style;

/// Print a success message: "ok: <message>"
pub fn ok(message: &str) {
    eprintln!("{} {}", style("ok:").green().bold(), message);
}

/// Print an error message: "error: <message>"
pub fn error(message: &str) {
    eprintln!("{} {}", style("error:").red().bold(), message);
}

/// Print a warning message: "warning: <message>"
pub fn warning(message: &str) {
    eprintln!("{} {}", style("warning:").yellow().bold(), message);
}

/// Print an info line (label: value) for share/receive metadata display.
pub fn info(label: &str, value: &str) {
    eprintln!("  {:<14}{}", style(label).bold(), value);
}
