use super::{DisplayDriver, DisplayState};

/// Renders the status screen to the tracing log. This is the default driver used
/// on any host without the `hardware` feature (or when e-paper init fails), so the
/// same status content can be developed and verified without physical hardware.
pub struct MockDisplay;

impl MockDisplay {
    pub fn new() -> Self {
        MockDisplay
    }
}

impl Default for MockDisplay {
    fn default() -> Self {
        Self::new()
    }
}

impl DisplayDriver for MockDisplay {
    fn render(&mut self, state: &DisplayState) -> Result<(), String> {
        let lines = state.lines();
        let width = lines
            .iter()
            .map(|l| l.chars().count())
            .max()
            .unwrap_or(0)
            .max(12);
        let border = "─".repeat(width + 2);

        let mut out = String::new();
        out.push('\n');
        out.push_str(&format!("┌{}┐\n", border));
        for l in &lines {
            let pad = width.saturating_sub(l.chars().count());
            out.push_str(&format!("│ {}{} │\n", l, " ".repeat(pad)));
        }
        out.push_str(&format!("└{}┘", border));

        tracing::info!("[display]{}", out);
        Ok(())
    }
}
