use axum::{
    extract::Json,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

use crate::{analyzer, ast_analyzer, cargo_check, rules, dataflow, ownership, alias, cross_fn};

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AnalyzeRequest {
    pub rust_code: String,
    pub c_code: Option<String>,
    pub run_cargo_check: Option<bool>,
    pub mode: Option<String>,   // "regex", "ast", or "full"
}

#[derive(Serialize)]
pub struct AnalyzeResponse {
    pub issues: Vec<rules::Issue>,
    pub metrics: Metrics,
    pub summary: Summary,
    pub elapsed_ms: u64,
}

#[derive(Serialize)]
pub struct Metrics {
    pub sss: f64,
    pub uei: f64,
    pub vrr: usize,
    pub total_lines: usize,
    pub total_functions: usize,
}

#[derive(Serialize)]
pub struct Summary {
    pub errors: usize,
    pub warnings: usize,
    pub info: usize,
    pub hints: usize,
    pub total: usize,
}

// ── Server entry point ────────────────────────────────────────────────────────

pub async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/api/analyze", post(analyze_handler))
        .route("/health", get(health))
        .layer(cors);

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("🦀 RustGuard v0.3 web server running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Route handlers ────────────────────────────────────────────────────────────

async fn health() -> &'static str {
    "ok"
}

async fn serve_index() -> impl IntoResponse {
    let html = include_str!("../static/index.html");
    Html(html)
}

async fn analyze_handler(
    Json(req): Json<AnalyzeRequest>,
) -> Result<Json<AnalyzeResponse>, AppError> {
    let start = std::time::Instant::now();

    if req.rust_code.len() > 500_000 {
        return Err(AppError("Rust code exceeds 500 KB limit".to_string()));
    }
    if req.c_code.as_ref().map(|s| s.len()).unwrap_or(0) > 500_000 {
        return Err(AppError("C code exceeds 500 KB limit".to_string()));
    }

    let rust_code = req.rust_code.clone();
    let c_code = req.c_code.clone();
    let run_cargo = req.run_cargo_check.unwrap_or(false);
    // Default to "full" so existing behaviour is preserved when mode not sent
    let mode = req.mode.clone().unwrap_or_else(|| "full".to_string());

    let result = tokio::task::spawn_blocking(move || {
        run_analysis(&rust_code, c_code.as_deref(), run_cargo, &mode)
    })
    .await
    .map_err(|e| AppError(e.to_string()))??;

    let elapsed_ms = start.elapsed().as_millis() as u64;

    Ok(Json(AnalyzeResponse {
        issues: result.0,
        metrics: result.1,
        summary: result.2,
        elapsed_ms,
    }))
}

// ── Core analysis — mode-controlled layers ────────────────────────────────────
//
//  REGEX mode  → Layer 1 only  (fast pattern matching, ~2ms)
//  AST mode    → Layers 1-6    (full semantic analysis, ~50ms)
//  FULL mode   → Layers 1-6 + optional cargo check

fn run_analysis(
    rust_code: &str,
    c_code: Option<&str>,
    run_cargo: bool,
    mode: &str,
) -> Result<(Vec<rules::Issue>, Metrics, Summary), AppError> {
    let mut all_issues: Vec<rules::Issue> = Vec::new();

    // ── Layer 1: regex + structural + CVE retention (always runs) ─────────
    let mut a = analyzer::Analyzer::new(rust_code.to_string(), c_code.map(|s| s.to_string()));
    all_issues.extend(a.run());

    // ── Layers 2-6: only in AST or FULL mode ─────────────────────────────
    if mode == "ast" || mode == "full" {

        // Layer 2: AST structural (syn)
        match ast_analyzer::analyze(rust_code) {
            Ok(issues) => all_issues.extend(issues),
            Err(e) => {
                all_issues.push(rules::Issue {
                    line: 0, column: 0,
                    severity: rules::Severity::Error,
                    category: rules::Category::Syntax,
                    code: "AST000".to_string(),
                    message: format!("AST parse failed: {}", e),
                    suggestion: Some("Fix syntax errors before deeper analysis.".to_string()),
                    snippet: String::new(),
                });
            }
        }

        // Layer 3: Data-flow taint analysis (LLM hallucination detection)
        match dataflow::analyze(rust_code) {
            Ok(issues) => all_issues.extend(issues),
            Err(_) => {}
        }

        // Layer 4: Ownership graph
        match ownership::analyze(rust_code) {
            Ok(issues) => all_issues.extend(issues),
            Err(_) => {}
        }

        // Layer 5: Alias / union detection
        match alias::analyze(rust_code) {
            Ok(issues) => all_issues.extend(issues),
            Err(_) => {}
        }

        // Layer 6: Cross-function semantic analysis
        match cross_fn::analyze(rust_code) {
            Ok(issues) => all_issues.extend(issues),
            Err(_) => {}
        }
    }

    // ── Layer 7: cargo check (FULL mode only, and only if user enabled it) ─
    if mode == "full" && run_cargo {
        match cargo_check::run(rust_code, None) {
            Ok(issues) => all_issues.extend(issues),
            Err(_) => {}
        }
    }

    // ── Compute Objective 3 metrics ───────────────────────────────────────
    let total_lines     = rust_code.lines().count();
    let total_functions = rust_code.matches("fn ").count();

    let semantic_issues = all_issues.iter()
        .filter(|i| matches!(i.category,
            rules::Category::Semantic
            | rules::Category::Memory
            | rules::Category::Aliasing
            | rules::Category::Ownership
            | rules::Category::LlmHallucination
            | rules::Category::CveRetention))
        .count();

    // SSS: Semantic Safety Score
    let sss = if total_functions > 0 {
        let unsafe_fns = semantic_issues.min(total_functions);
        ((total_functions - unsafe_fns) as f64 / total_functions as f64) * 100.0
    } else {
        100.0
    };

    // UEI: Unsafe Exposure Index
    let unsafe_issues = all_issues.iter()
        .filter(|i| matches!(i.code.as_str(),
            "RAW001" | "RAW002" | "AST_FN002" | "AST_UNS001" | "AST_UNS002"
            | "ALIAS001" | "ALIAS002" | "LLM_PAT001"))
        .count();
    let uei = if !all_issues.is_empty() {
        (unsafe_issues as f64 / all_issues.len() as f64) * 100.0
    } else {
        0.0
    };

    // VRR: Vulnerability Retention Rate (Wu et al. 2025)
    let vrr = all_issues.iter()
        .filter(|i| i.code.starts_with("VRR_") && !i.code.ends_with("_SAFE"))
        .count();

    let metrics = Metrics { sss, uei, vrr, total_lines, total_functions };

    let summary = Summary {
        errors:   all_issues.iter().filter(|i| matches!(i.severity, rules::Severity::Error)).count(),
        warnings: all_issues.iter().filter(|i| matches!(i.severity, rules::Severity::Warning)).count(),
        info:     all_issues.iter().filter(|i| matches!(i.severity, rules::Severity::Info)).count(),
        hints:    all_issues.iter().filter(|i| matches!(i.severity, rules::Severity::Hint)).count(),
        total:    all_issues.len(),
    };

    Ok((all_issues, metrics, summary))
}

// ── Error type ────────────────────────────────────────────────────────────────

pub struct AppError(String);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "application/json")],
            format!(r#"{{"error":"{}"}}"#, self.0),
        )
            .into_response()
    }
}

impl From<Box<dyn std::error::Error>> for AppError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        AppError(e.to_string())
    }
}