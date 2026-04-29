use crate::rules::{Issue, Severity};
use colored::*;
use std::collections::HashMap;

pub struct Report {
    issues: Vec<Issue>,
    verbose: u8,
}

impl Report {
    pub fn new(issues: Vec<Issue>, verbose: u8) -> Self {
        Self { issues, verbose }
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let mut by_category: HashMap<String, Vec<&Issue>> = HashMap::new();

        for issue in &self.issues {
            let key = format!("{:?}", issue.category);
            by_category.entry(key).or_default().push(issue);
        }

        out.push_str(&format!("\n{}\n", "── Summary ──".bold()));
        out.push_str(&format!("Total issues: {}\n", self.issues.len()));

        let errors = self.issues.iter().filter(|i| matches!(i.severity, Severity::Error)).count();
        let warnings = self.issues.iter().filter(|i| matches!(i.severity, Severity::Warning)).count();
        let infos = self.issues.iter().filter(|i| matches!(i.severity, Severity::Info)).count();
        let hints = self.issues.iter().filter(|i| matches!(i.severity, Severity::Hint)).count();

        out.push_str(&format!("  {} Errors: {}\n", "X".red(), errors));
        out.push_str(&format!("  {} Warnings: {}\n", "!".yellow(), warnings));
        out.push_str(&format!("  {} Info: {}\n", "i".blue(), infos));
        out.push_str(&format!("  {} Hints: {}\n", "*".cyan(), hints));

        for (cat, items) in &by_category {
            out.push_str(&format!("\n{} {} ({})\n",
                "──".white(), cat.bold(), items.len()));

            for issue in items {
                let sev_marker = match issue.severity {
                    Severity::Error => "X".red(),
                    Severity::Warning => "!".yellow(),
                    Severity::Info => "i".blue(),
                    Severity::Hint => "*".cyan(),
                };

                if issue.line > 0 {
                    out.push_str(&format!(
                        "  {} [{}] line {}:{} — {}\n",
                        sev_marker,
                        issue.code.bright_white(),
                        issue.line,
                        issue.column,
                        issue.message
                    ));
                } else {
                    out.push_str(&format!(
                        "  {} [{}] {}\n",
                        sev_marker,
                        issue.code.bright_white(),
                        issue.message
                    ));
                }

                if self.verbose >= 1 && !issue.snippet.is_empty() {
                    out.push_str(&format!("      | {}\n", issue.snippet.dimmed()));
                }

                if self.verbose >= 1 {
                    if let Some(s) = &issue.suggestion {
                        out.push_str(&format!("      -> {}\n", s.green()));
                    }
                }
            }
        }

        out
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.issues)
    }
}