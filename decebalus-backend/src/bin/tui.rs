//! Decebalus terminal war table — a thin operator client over the running server's
//! REST API. Shows ranked findings and hosts, and lets you run the rule engine,
//! run/dismiss a finding, and copy its command, all from the keyboard.
//!
//! Build & run (needs the server on http://localhost:8080, or set DECEBALUS_URL):
//!   cargo run --features tui --bin decebalus-tui

use std::error::Error;
use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{execute, ExecutableCommand};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
struct Finding {
    id: String,
    title: String,
    value_score: i64,
    severity: String,
    status: String,
    #[serde(default)]
    rationale: String,
    #[serde(default)]
    suggested_command: Option<String>,
    #[serde(default)]
    job_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PortLite {
    status: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Host {
    ip: String,
    #[serde(default)]
    hostname: Option<String>,
    status: String,
    #[serde(default)]
    ports: Vec<PortLite>,
}

struct App {
    base: String,
    token: Option<String>,
    client: reqwest::Client,
    findings: Vec<Finding>,
    hosts: Vec<Host>,
    state: ListState,
    status: String,
}

impl App {
    fn new(base: String) -> Self {
        let mut state = ListState::default();
        state.select(Some(0));
        App {
            base,
            token: std::env::var("DECEBALUS_TOKEN").ok().filter(|t| !t.is_empty()),
            client: reqwest::Client::new(),
            findings: Vec::new(),
            hosts: Vec::new(),
            state,
            status: "Loading…".into(),
        }
    }

    /// A GET builder with bearer auth applied when DECEBALUS_TOKEN is set.
    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        let rb = self.client.get(format!("{}{}", self.base, path));
        match &self.token { Some(t) => rb.bearer_auth(t), None => rb }
    }

    /// A POST builder with bearer auth applied when DECEBALUS_TOKEN is set.
    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        let rb = self.client.post(format!("{}{}", self.base, path));
        match &self.token { Some(t) => rb.bearer_auth(t), None => rb }
    }

    async fn refresh(&mut self) {
        match self.get("/api/findings").send().await {
            Ok(r) => self.findings = r.json::<Vec<Finding>>().await.unwrap_or_default(),
            Err(e) => self.status = format!("findings error: {e}"),
        }
        // Keep only actionable findings, ranked (server already sorts by value).
        self.findings.retain(|f| f.status != "dismissed");
        match self.get("/api/hosts").send().await {
            Ok(r) => self.hosts = r.json::<Vec<Host>>().await.unwrap_or_default(),
            Err(e) => self.status = format!("hosts error: {e}"),
        }
        let sel = self.state.selected().unwrap_or(0);
        if sel >= self.findings.len() {
            self.state.select(if self.findings.is_empty() { None } else { Some(self.findings.len() - 1) });
        }
        self.status = format!("{} findings · {} hosts · {}", self.findings.len(), self.hosts.len(), self.base);
    }

    fn selected(&self) -> Option<&Finding> {
        self.state.selected().and_then(|i| self.findings.get(i))
    }

    fn next(&mut self) {
        if self.findings.is_empty() {
            return;
        }
        let i = self.state.selected().map(|i| (i + 1) % self.findings.len()).unwrap_or(0);
        self.state.select(Some(i));
    }

    fn prev(&mut self) {
        if self.findings.is_empty() {
            return;
        }
        let i = self
            .state
            .selected()
            .map(|i| if i == 0 { self.findings.len() - 1 } else { i - 1 })
            .unwrap_or(0);
        self.state.select(Some(i));
    }

    async fn run_engine(&mut self) {
        self.status = "running rule engine…".into();
        let _ = self.post("/api/engine/run").send().await;
        self.refresh().await;
    }

    async fn run_selected(&mut self) {
        let Some(f) = self.selected().cloned() else { return };
        if f.job_type.is_none() {
            self.status = "finding has no runnable job".into();
            return;
        }
        self.status = format!("running: {}", f.title);
        let _ = self.post(&format!("/api/findings/{}/run", f.id)).send().await;
        self.refresh().await;
    }

    async fn dismiss_selected(&mut self) {
        let Some(f) = self.selected().cloned() else { return };
        let _ = self.post(&format!("/api/findings/{}/dismiss", f.id)).send().await;
        self.refresh().await;
    }
}

fn sev_color(sev: &str) -> Color {
    match sev {
        "critical" => Color::Magenta,
        "high" => Color::Red,
        "medium" => Color::Yellow,
        "low" => Color::Cyan,
        _ => Color::Gray,
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3), Constraint::Length(1)])
        .split(f.area());

    // Title bar.
    let title = Line::from(vec![
        Span::styled(" DECEBALUS ", Style::default().fg(Color::Black).bg(Color::Rgb(196, 132, 74)).add_modifier(Modifier::BOLD)),
        Span::raw(" war table — "),
        Span::styled(&app.status, Style::default().fg(Color::Gray)),
    ]);
    f.render_widget(Paragraph::new(title), rows[0]);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(rows[1]);

    // Findings list.
    let items: Vec<ListItem> = app
        .findings
        .iter()
        .map(|fd| {
            let line = Line::from(vec![
                Span::styled(format!("{:>3} ", fd.value_score), Style::default().fg(Color::Rgb(214, 158, 106)).add_modifier(Modifier::BOLD)),
                Span::styled(format!("{:<8} ", fd.severity), Style::default().fg(sev_color(&fd.severity))),
                Span::raw(fd.title.clone()),
                Span::styled(format!("  [{}]", fd.status), Style::default().fg(Color::DarkGray)),
            ]);
            ListItem::new(line)
        })
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Ranked next moves "))
        .highlight_style(Style::default().bg(Color::Rgb(60, 45, 30)).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, cols[0], &mut app.state);

    // Right column: selected detail (top) + hosts (bottom).
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(cols[1]);

    let detail = if let Some(fd) = app.selected() {
        let mut lines = vec![
            Line::from(Span::styled(fd.title.clone(), Style::default().add_modifier(Modifier::BOLD))),
            Line::raw(""),
            Line::raw(fd.rationale.clone()),
        ];
        if let Some(cmd) = &fd.suggested_command {
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled("command:", Style::default().fg(Color::Gray))));
            lines.push(Line::from(Span::styled(cmd.clone(), Style::default().fg(Color::Green))));
        }
        Paragraph::new(lines).wrap(Wrap { trim: true })
    } else {
        Paragraph::new("No finding selected.")
    };
    f.render_widget(detail.block(Block::default().borders(Borders::ALL).title(" Detail ")), right[0]);

    let host_items: Vec<ListItem> = app
        .hosts
        .iter()
        .map(|h| {
            let open = h.ports.iter().filter(|p| p.status == "open").count();
            let dot = if h.status == "Up" { Span::styled("● ", Style::default().fg(Color::Green)) } else { Span::styled("● ", Style::default().fg(Color::Red)) };
            ListItem::new(Line::from(vec![
                dot,
                Span::raw(format!("{:<16}", h.ip)),
                Span::styled(format!("{:<16}", h.hostname.clone().unwrap_or_else(|| "—".into())), Style::default().fg(Color::Gray)),
                Span::raw(format!("{} ports", open)),
            ]))
        })
        .collect();
    f.render_widget(
        List::new(host_items).block(Block::default().borders(Borders::ALL).title(" Hosts ")),
        right[1],
    );

    // Help line.
    let help = Line::from(Span::styled(
        " q quit · r refresh · e run engine · ⏎ run · d dismiss · ↑/↓ or j/k move ",
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(Paragraph::new(help), rows[2]);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let base = std::env::var("DECEBALUS_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let mut app = App::new(base);
    app.refresh().await;
    let mut last = Instant::now();

    let result = loop {
        if let Err(e) = terminal.draw(|f| ui(f, &mut app)) {
            break Err::<(), Box<dyn Error>>(e.into());
        }
        match event::poll(Duration::from_millis(250)) {
            Ok(true) => {
                if let Ok(Event::Key(k)) = event::read() {
                    if k.kind == KeyEventKind::Press {
                        match k.code {
                            KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                            KeyCode::Char('r') => app.refresh().await,
                            KeyCode::Char('e') => app.run_engine().await,
                            KeyCode::Char('d') => app.dismiss_selected().await,
                            KeyCode::Enter => app.run_selected().await,
                            KeyCode::Down | KeyCode::Char('j') => app.next(),
                            KeyCode::Up | KeyCode::Char('k') => app.prev(),
                            _ => {}
                        }
                    }
                }
            }
            Ok(false) => {}
            Err(e) => break Err(e.into()),
        }
        if last.elapsed() > Duration::from_secs(2) {
            app.refresh().await;
            last = Instant::now();
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}
