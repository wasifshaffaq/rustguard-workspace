use crate::rules::{Issue, Severity, Category};
use serde::Deserialize;
use std::path::Path;
use std::process::Command;
use std::io::Write;

#[derive(Debug, Deserialize)]
struct CargoMessage {
    reason: Option<String>,
    message: Option<DiagnosticMessage>,
}

#[derive(Debug, Deserialize)]
struct DiagnosticMessage {
    message: String,
    code: Option<DiagnosticCode>,
    level: String,
    spans: Vec<DiagnosticSpan>,
    children: Vec<DiagnosticChild>,
}

#[derive(Debug, Deserialize)]
struct DiagnosticCode {
    code: String,
}

#[derive(Debug, Deserialize)]
struct DiagnosticSpan {
    line_start: usize,
    column_start: usize,
    is_primary: bool,
}

#[derive(Debug, Deserialize)]
struct DiagnosticChild {
    message: String,
    level: String,
}

pub fn run(rust_code: &str, project_root: Option<&Path>)
    -> Result<Vec<Issue>, Box<dyn std::error::Error>>
{
    let (working_dir, _temp_guard) = match project_root {
        Some(p) => (p.to_path_buf(), None),
        None => {
            let temp_dir = tempfile::tempdir()?;
            let temp_path = temp_dir.path().to_path_buf();
            scaffold_temp_project(&temp_path, rust_code)?;
            (temp_path, Some(temp_dir))
        }
    };

    let output = Command::new("cargo")
        .arg("check")
        .arg("--message-format=json")
        .arg("--quiet")
        .current_dir(&working_dir)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut issues = Vec::new();

    for line in stdout.lines() {
        if line.is_empty() { continue; }
        let parsed: Result<CargoMessage, _> = serde_json::from_str(line);
        if let Ok(msg) = parsed {
            if msg.reason.as_deref() != Some("compiler-message") { continue; }
            let diag = match msg.message {
                Some(d) => d,
                None => continue,
            };

            let primary = diag.spans.iter().find(|s| s.is_primary);
            let (line_no, col) = match primary {
                Some(s) => (s.line_start, s.column_start),
                None => (0, 0),
            };

            let severity = match diag.level.as_str() {
                "error" => Severity::Error,
                "warning" => Severity::Warning,
                "note" => Severity::Info,
                "help" => Severity::Hint,
                _ => Severity::Info,
            };

            let code = diag.code.map(|c| c.code).unwrap_or_else(|| "RUSTC".to_string());

            let suggestion = diag.children.iter()
                .filter(|c| c.level == "help")
                .map(|c| c.message.clone())
                .collect::<Vec<_>>()
                .join("; ");

            issues.push(Issue {
                line: line_no,
                column: col,
                severity,
                category: Category::Semantic,
                code: format!("RUSTC_{}", code),
                message: diag.message,
                suggestion: if suggestion.is_empty() { None } else { Some(suggestion) },
                snippet: String::new(),
            });
        }
    }

    Ok(issues)
}

fn scaffold_temp_project(path: &Path, rust_code: &str)
    -> Result<(), Box<dyn std::error::Error>>
{
    use std::fs;

    let src_dir = path.join("src");
    fs::create_dir_all(&src_dir)?;

    let cargo_toml = r#"[package]
name = "transpile_check"
version = "0.0.1"
edition = "2021"

[lib]
path = "src/lib.rs"
"#;
    fs::write(path.join("Cargo.toml"), cargo_toml)?;

    let mut f = fs::File::create(src_dir.join("lib.rs"))?;
    f.write_all(b"#![allow(unused, dead_code, unused_imports, unused_variables)]\n")?;
    f.write_all(rust_code.as_bytes())?;

    Ok(())
}