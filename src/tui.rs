use crate::models::{Finding, RuleId, Severity};
use crate::scanner;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct App {
    path_input: String,
    all_findings: Vec<Finding>,
    filtered: Vec<Finding>,
    table_state: TableState,
    severity_filter: Option<Severity>,
    rule_filter: Option<RuleId>,
    status: String,
    show_help: bool,
    editing_path: bool,
    should_quit: bool,
}

impl App {
    fn new(initial: &Path) -> Self {
        let mut app = Self {
            path_input: initial.display().to_string(),
            all_findings: Vec::new(),
            filtered: Vec::new(),
            table_state: TableState::default(),
            severity_filter: None,
            rule_filter: None,
            status: "Press Enter/F5 to scan · ? help · q quit".into(),
            show_help: false,
            editing_path: false,
            should_quit: false,
        };
        let _ = app.run_scan();
        app
    }

    fn run_scan(&mut self) -> Result<()> {
        let target = PathBuf::from(self.path_input.trim());
        if !target.exists() {
            self.status = format!("Path not found: {}", target.display());
            self.all_findings.clear();
            self.filtered.clear();
            return Ok(());
        }
        self.status = format!("Scanning {}…", target.display());
        let findings = scanner::scan_path(&target)?;
        self.all_findings = findings;
        self.severity_filter = None;
        self.rule_filter = None;
        self.apply_filters();
        Ok(())
    }

    fn apply_filters(&mut self) {
        self.filtered = self
            .all_findings
            .iter()
            .filter(|f| {
                self.severity_filter
                    .map(|s| f.severity == s)
                    .unwrap_or(true)
                    && self.rule_filter.map(|r| f.rule_id == r).unwrap_or(true)
            })
            .cloned()
            .collect();

        if self.filtered.is_empty() {
            self.table_state.select(None);
        } else if self.table_state.selected().is_none() {
            self.table_state.select(Some(0));
        } else if let Some(i) = self.table_state.selected() {
            if i >= self.filtered.len() {
                self.table_state.select(Some(self.filtered.len() - 1));
            }
        }

        let mut c = [0usize; 4];
        for f in &self.all_findings {
            c[f.severity.rank() as usize] += 1;
        }
        let mut filter = String::new();
        if let Some(s) = self.severity_filter {
            filter.push_str(&format!(" sev={s}"));
        }
        if let Some(r) = self.rule_filter {
            filter.push_str(&format!(" rule={r}"));
        }
        self.status = format!(
            "findings: {} (showing {}) | CRIT {} HIGH {} MED {} LOW {}{}",
            self.all_findings.len(),
            self.filtered.len(),
            c[0],
            c[1],
            c[2],
            c[3],
            filter
        );
    }

    fn cycle_severity(&mut self) {
        let order = [
            None,
            Some(Severity::Critical),
            Some(Severity::High),
            Some(Severity::Medium),
            Some(Severity::Low),
        ];
        let idx = order
            .iter()
            .position(|x| *x == self.severity_filter)
            .unwrap_or(0);
        self.severity_filter = order[(idx + 1) % order.len()];
        self.apply_filters();
    }

    fn cycle_rule(&mut self) {
        let mut order: Vec<Option<RuleId>> = vec![None];
        order.extend(RuleId::all().iter().copied().map(Some));
        let idx = order
            .iter()
            .position(|x| *x == self.rule_filter)
            .unwrap_or(0);
        self.rule_filter = order[(idx + 1) % order.len()];
        self.apply_filters();
    }

    fn selected_finding(&self) -> Option<&Finding> {
        self.table_state
            .selected()
            .and_then(|i| self.filtered.get(i))
    }

    fn move_sel(&mut self, delta: isize) {
        if self.filtered.is_empty() {
            return;
        }
        let len = self.filtered.len() as isize;
        let cur = self.table_state.selected().unwrap_or(0) as isize;
        let next = (cur + delta).rem_euclid(len) as usize;
        self.table_state.select(Some(next));
    }
}

pub fn run(initial: &Path) -> Result<()> {
    let mut terminal = ratatui::init();
    let result = run_app(&mut terminal, initial);
    ratatui::restore();
    result
}

fn run_app(terminal: &mut Terminal<impl Backend>, initial: &Path) -> Result<()> {
    let mut app = App::new(initial);
    loop {
        terminal.draw(|f| ui(f, &mut app))?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                handle_key(&mut app, key.code)?;
            }
        }
        if app.should_quit {
            break;
        }
    }
    Ok(())
}

fn handle_key(app: &mut App, code: KeyCode) -> Result<()> {
    if app.show_help {
        app.show_help = false;
        return Ok(());
    }

    if app.editing_path {
        match code {
            KeyCode::Esc => app.editing_path = false,
            KeyCode::Enter => {
                app.editing_path = false;
                app.run_scan()?;
            }
            KeyCode::Backspace => {
                app.path_input.pop();
            }
            KeyCode::Char(c) => app.path_input.push(c),
            _ => {}
        }
        return Ok(());
    }

    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('?') => app.show_help = true,
        KeyCode::Char('/') => app.editing_path = true,
        KeyCode::Char('f') => app.cycle_severity(),
        KeyCode::Char('r') => app.cycle_rule(),
        KeyCode::F(5) | KeyCode::Enter => app.run_scan()?,
        KeyCode::Up | KeyCode::Char('k') => app.move_sel(-1),
        KeyCode::Down | KeyCode::Char('j') => app.move_sel(1),
        _ => {}
    }
    Ok(())
}

fn ui(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(8),
            Constraint::Length(8),
            Constraint::Length(1),
        ])
        .split(area);

    let path_title = if app.editing_path {
        " Path (editing — Enter scan, Esc cancel) "
    } else {
        " Path (/ to edit, Enter/F5 scan) "
    };
    let path = Paragraph::new(app.path_input.as_str())
        .block(Block::default().borders(Borders::ALL).title(path_title));
    frame.render_widget(path, chunks[0]);

    let status = Paragraph::new(app.status.as_str()).style(Style::default().fg(Color::Cyan));
    frame.render_widget(status, chunks[1]);

    let header = Row::new(["Sev", "Rule", "Resource", "NS", "File"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(0);

    let rows: Vec<Row> = app
        .filtered
        .iter()
        .map(|f| {
            let color = match f.severity {
                Severity::Critical => Color::Red,
                Severity::High => Color::LightRed,
                Severity::Medium => Color::Yellow,
                Severity::Low => Color::Cyan,
            };
            let file = Path::new(&f.file)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&f.file);
            Row::new(vec![
                Cell::from(f.severity.as_str()).style(Style::default().fg(color)),
                Cell::from(f.rule_id.as_str()),
                Cell::from(f.resource.as_str()),
                Cell::from(f.namespace.as_str()),
                Cell::from(file),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(9),
        Constraint::Length(18),
        Constraint::Percentage(35),
        Constraint::Length(12),
        Constraint::Percentage(30),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(" Findings "))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, chunks[2], &mut app.table_state);

    let detail = match app.selected_finding() {
        Some(f) => {
            let container = f
                .container
                .as_ref()
                .map(|c| format!("\nContainer: {c}"))
                .unwrap_or_default();
            format!(
                "{}  {}\nResource: {}\nNamespace: {}{}\nFile: {}\n\n{}",
                f.severity.as_str(),
                f.rule_id.label(),
                f.resource,
                f.namespace,
                container,
                f.file,
                f.message
            )
        }
        None => "Select a finding to see details.".into(),
    };
    let detail_w = Paragraph::new(detail)
        .wrap(ratatui::widgets::Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL).title(" Details "));
    frame.render_widget(detail_w, chunks[3]);

    let footer = Paragraph::new("q quit · ? help · f severity · r rule · / path · ↑↓ navigate")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, chunks[4]);

    if app.show_help {
        let help = Paragraph::new(
            "kubeyamyam — Kubernetes manifest security scanner\n\n\
             Checks: PRIV · HOSTPATH · LATEST · LIMITS · SA-DEFAULT · SA-AUTOMOUNT · SA-CLUSTERADMIN\n\n\
             Keys:\n\
               Enter / F5   Scan\n\
               /            Edit path\n\
               f / r        Cycle severity / rule filters\n\
               j/k or ↑↓    Navigate\n\
               q            Quit\n\n\
             Press any key to close.",
        )
        .block(Block::default().borders(Borders::ALL).title(" Help "));
        let area = centered_rect(70, 60, frame.area());
        frame.render_widget(Clear, area);
        frame.render_widget(help, area);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup[1])[1]
}

// Silence unused import warning on some platforms
#[allow(dead_code)]
fn _io_marker() -> io::Result<()> {
    Ok(())
}
