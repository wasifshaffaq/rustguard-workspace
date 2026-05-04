mod analyzer;
mod rules;
mod report;
mod ast_analyzer;
mod cargo_check;
mod dataflow;
mod ownership;
mod alias;
mod cross_fn;
mod cve_retention;
mod server;

use clap::Parser;
use colored::*;
use std::path::PathBuf;
use std::fs;

#[derive(Parser, Debug)]
#[command(name = "cpp2rust-debugger")]
#[command(about = "RustGuard v0.3 — Heuristic Semantic Analyser for C→Rust Transpilation")]
struct Args {
    #[arg(short, long, help = "Original C/C++ source file (enables CVE retention analysis)")]
    cpp: Option<PathBuf>,

    #[arg(short, long, help = "Transpiled Rust file or Cargo project directory")]
    rust: PathBuf,

    #[arg(short, long, default_value = "text", help = "Output format: text or json")]
    format: String,

    #[arg(short, long, help = "Write output to file")]
    output: Option<PathBuf>,

    #[arg(short, long, default_value = "1", help = "Verbosity: 0=minimal, 1=standard, 2=full")]
    verbose: u8,

    #[arg(long, help = "Skip cargo check (faster)")]
    no_cargo_check: bool,

    #[arg(long, help = "Skip AST analysis")]
    no_ast: bool,

    #[arg(long, help = "Skip regex pattern matching")]
    no_regex: bool,

    #[arg(long, help = "Skip data-flow taint analysis")]
    no_dataflow: bool,

    #[arg(long, help = "Skip ownership graph analysis")]
    no_ownership: bool,

    #[arg(long, help = "Skip alias / union analysis")]
    no_alias: bool,

    #[arg(long, help = "Skip cross-function semantic analysis")]
    no_cross: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw_args: Vec<String> = std::env::args().collect();

    // If no arguments given, or --server flag present → run as web server (Railway/hosting mode)
    // When Railway runs ./cpp2rust-debugger with no args, this triggers the web server
    if raw_args.len() == 1 || raw_args.iter().any(|a| a == "--server") {
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(server::run_server());
    }

    // Otherwise → run as CLI tool (local usage with --rust flag)
    let args = Args::parse();

    println!("{}", "═══════════════════════════════════════════════════".cyan());
    println!("{}", " RustGuard v0.3 — C→Rust Transpilation Analyser    ".cyan().bold());
    println!("{}", " Based on Wu et al. (2025) | IEEE TrustCom          ".cyan());
    println!("{}", "═══════════════════════════════════════════════════".cyan());

    // ── Load source files ─────────────────────────────────────────────────
    let rust_path = &args.rust;
    let (rust_code, project_root) = if rust_path.is_dir() {
        let main_rs = rust_path.join("src").join("main.rs");
        let lib_rs  = rust_path.join("src").join("lib.rs");
        let target  = if main_rs.exists() { main_rs }
                      else if lib_rs.exists() { lib_rs }
                      else { return Err("Cargo project missing src/main.rs or src/lib.rs".into()); };
        (fs::read_to_string(&target)?, Some(rust_path.clone()))
    } else {
        (fs::read_to_string(rust_path)?, None)
    };

    let cpp_code = match &args.cpp {
        Some(path) => Some(fs::read_to_string(path)?),
        None => None,
    };

    let mut all_issues = Vec::new();

    // ── Layer 1: Regex + structural + CVE retention ───────────────────────
    if !args.no_regex {
        println!("{}", "→ [Layer 1] Pattern + structural + CVE retention analysis...".dimmed());
        let mut a = analyzer::Analyzer::new(rust_code.clone(), cpp_code.clone());
        all_issues.extend(a.run());
    }

    // ── Layer 2: AST structural ───────────────────────────────────────────
    if !args.no_ast {
        println!("{}", "→ [Layer 2] AST structural analysis (syn)...".dimmed());
        match ast_analyzer::analyze(&rust_code) {
            Ok(issues) => all_issues.extend(issues),
            Err(e) => {
                eprintln!("{} AST parse failed: {}", "⚠".yellow(), e);
                all_issues.push(rules::Issue {
                    line: 0, column: 0,
                    severity: rules::Severity::Error,
                    category: rules::Category::Syntax,
                    code: "AST000".to_string(),
                    message: format!("syn could not parse file: {}", e),
                    suggestion: Some("Fix syntax errors before deeper analysis.".to_string()),
                    snippet: String::new(),
                });
            }
        }
    }

    // ── Layer 3: Data-flow taint analysis ─────────────────────────────────
    if !args.no_dataflow {
        println!("{}", "→ [Layer 3] Data-flow taint analysis (LLM hallucination detection)...".dimmed());
        match dataflow::analyze(&rust_code) {
            Ok(issues) => {
                let n = issues.len();
                all_issues.extend(issues);
                if n > 0 {
                    println!("  {} data-flow issues found", n.to_string().yellow());
                }
            }
            Err(e) => eprintln!("  Data-flow analysis failed: {}", e),
        }
    }

    // ── Layer 4: Ownership graph ──────────────────────────────────────────
    if !args.no_ownership {
        println!("{}", "→ [Layer 4] Ownership graph analysis...".dimmed());
        match ownership::analyze(&rust_code) {
            Ok(issues) => {
                let n = issues.len();
                all_issues.extend(issues);
                if n > 0 {
                    println!("  {} ownership issues found", n.to_string().yellow());
                }
            }
            Err(e) => eprintln!("  Ownership analysis failed: {}", e),
        }
    }

    // ── Layer 5: Alias / union analysis ──────────────────────────────────
    if !args.no_alias {
        println!("{}", "→ [Layer 5] Alias and union semantics analysis...".dimmed());
        match alias::analyze(&rust_code) {
            Ok(issues) => {
                let n = issues.len();
                all_issues.extend(issues);
                if n > 0 {
                    println!("  {} aliasing issues found", n.to_string().yellow());
                }
            }
            Err(e) => eprintln!("  Alias analysis failed: {}", e),
        }
    }

    // ── Layer 6: Cross-function semantic analysis ─────────────────────────
    if !args.no_cross {
        println!("{}", "→ [Layer 6] Cross-function semantic analysis...".dimmed());
        match cross_fn::analyze(&rust_code) {
            Ok(issues) => {
                let n = issues.len();
                all_issues.extend(issues);
                if n > 0 {
                    println!("  {} cross-function issues found", n.to_string().yellow());
                }
            }
            Err(e) => eprintln!("  Cross-function analysis failed: {}", e),
        }
    }

    // ── Layer 7 (optional): cargo check ──────────────────────────────────
    if !args.no_cargo_check {
        println!("{}", "→ [Layer 7] cargo check (may take a moment)...".dimmed());
        match cargo_check::run(&rust_code, project_root.as_deref()) {
            Ok(issues) => all_issues.extend(issues),
            Err(e) => eprintln!("  cargo check failed: {}", e),
        }
    }

    // ── Compute metrics ───────────────────────────────────────────────────
    let metrics = compute_metrics(&all_issues, &rust_code, cpp_code.as_deref());

    // ── Output ────────────────────────────────────────────────────────────
    let rep = report::Report::new(all_issues, args.verbose);
    let output_str = match args.format.as_str() {
        "json" => rep.to_json()?,
        _ => {
            let mut s = rep.to_text();
            s.push_str(&metrics);
            s
        }
    };

    match args.output {
        Some(path) => fs::write(path, output_str)?,
        None => println!("{}", output_str),
    }

    Ok(())
}

fn compute_metrics(
    issues: &[rules::Issue],
    rust_code: &str,
    c_code: Option<&str>,
) -> String {
    use rules::{Severity, Category};

    let total_lines = rust_code.lines().count();
    let total_fns   = rust_code.matches("fn ").count();

    let _errors   = issues.iter().filter(|i| matches!(i.severity, Severity::Error)).count();
    let _warnings = issues.iter().filter(|i| matches!(i.severity, Severity::Warning)).count();

    let semantic_issues = issues.iter()
        .filter(|i| matches!(i.category,
            Category::Semantic | Category::Memory | Category::Aliasing |
            Category::Ownership | Category::LlmHallucination | Category::CveRetention))
        .count();

    // SSS: Semantic Safety Score
    let sss = if total_fns > 0 {
        let unsafe_fns = semantic_issues.min(total_fns);
        ((total_fns - unsafe_fns) as f64 / total_fns as f64) * 100.0
    } else { 100.0 };

    // UEI: Unsafe Exposure Index
    let unsafe_issues = issues.iter()
        .filter(|i| matches!(i.code.as_str(),
            "RAW001" | "RAW002" | "AST_FN002" | "AST_UNS001" | "AST_UNS002" |
            "ALIAS001" | "ALIAS002" | "LLM_PAT001"))
        .count();
    let uei = if !issues.is_empty() {
        (unsafe_issues as f64 / issues.len() as f64) * 100.0
    } else { 0.0 };

    // VRR: Vulnerability Retention Rate
    let vrr = issues.iter()
        .filter(|i| i.code.starts_with("VRR_") && !i.code.ends_with("_SAFE"))
        .count();

    // LLM-specific bug count
    let llm_bugs = issues.iter()
        .filter(|i| i.code.starts_with("LLM_") || i.code.starts_with("OWN0"))
        .count();

    // Cross-function issues
    let cross_fn_bugs = issues.iter()
        .filter(|i| i.code.starts_with("CROSS_"))
        .count();

    // Aliasing issues
    let alias_bugs = issues.iter()
        .filter(|i| i.code.starts_with("ALIAS_"))
        .count();

    // FNR-ST: issues only our deep layers find (Clippy/cargo check would miss these)
    let deep_only = issues.iter()
        .filter(|i| {
            i.code.starts_with("LLM_") || i.code.starts_with("CROSS_") ||
            i.code.starts_with("ALIAS_STR") || i.code.starts_with("OWN0") ||
            i.code.starts_with("VRR_")
        })
        .count();

    let mut out = String::new();
    out.push_str(&format!("\n{}\n",
        "── Objective 3 Quality Metrics ─────────────────────────────".bold().cyan()));
    out.push_str(&format!(
        "  {:<40} {}\n",
        "SSS (Semantic Safety Score):".bold(),
        if sss >= 80.0 { format!("{:.1}%", sss).green().to_string() }
        else if sss >= 50.0 { format!("{:.1}%", sss).yellow().to_string() }
        else { format!("{:.1}%", sss).red().to_string() }
    ));
    out.push_str(&format!(
        "  {:<40} {}\n",
        "UEI (Unsafe Exposure Index):".bold(),
        if uei > 30.0 { format!("{:.1}%", uei).red().to_string() }
        else if uei > 10.0 { format!("{:.1}%", uei).yellow().to_string() }
        else { format!("{:.1}%", uei).green().to_string() }
    ));
    out.push_str(&format!(
        "  {:<40} {}\n",
        "VRR (Vulnerability Retention Rate):".bold(),
        if vrr > 0 { vrr.to_string().red() } else { "0 ✓".green() }
    ));
    out.push_str(&format!(
        "  {:<40} {}\n",
        "LLM-specific bugs detected:".bold(),
        if llm_bugs > 0 { llm_bugs.to_string().yellow() } else { "0 ✓".green() }
    ));
    out.push_str(&format!(
        "  {:<40} {}\n",
        "Cross-function issues:".bold(),
        cross_fn_bugs.to_string().normal()
    ));
    out.push_str(&format!(
        "  {:<40} {}\n",
        "Aliasing issues:".bold(),
        alias_bugs.to_string().normal()
    ));
    out.push_str(&format!(
        "  {:<40} {}\n",
        "FNR-ST (issues Clippy would miss):".bold(),
        deep_only.to_string().cyan()
    ));
    out.push_str(&format!(
        "  {:<40} {} lines, {} functions\n",
        "Codebase:".bold(), total_lines, total_fns
    ));
    out.push_str(&format!(
        "  {:<40} {}{}\n",
        "Analysis layers run:".bold(),
        "regex + AST + dataflow + ownership + alias + cross_fn",
        if c_code.is_some() { " + cve_retention" } else { "" }
    ));

    out
}