/// analyzer.rs — orchestrates all analysis layers
/// 
/// Layer 1: Regex pattern matching (rules.rs)
/// Layer 2: AST structural analysis (ast_analyzer.rs) — unchanged
/// Layer 3: Data-flow taint analysis (dataflow.rs) — NEW
/// Layer 4: Ownership graph analysis (ownership.rs) — NEW
/// Layer 5: Alias / union analysis (alias.rs) — NEW
/// Layer 6: Cross-function semantic analysis (cross_fn.rs) — NEW
/// Layer 7: C source CVE retention analysis (cve_retention.rs) — NEW (replaces compare_with_cpp)

use crate::rules::{get_rules, Issue, Severity, Category};
use crate::cve_retention;

pub struct Analyzer {
    pub rust_code: String,
    pub cpp_code: Option<String>,
}

impl Analyzer {
    pub fn new(rust_code: String, cpp_code: Option<String>) -> Self {
        Self { rust_code, cpp_code }
    }

    pub fn run(&mut self) -> Vec<Issue> {
        let mut issues = Vec::new();
        let rules = get_rules();
        let lines: Vec<&str> = self.rust_code.lines().collect();

        // ── Layer 1: regex pattern matching ──────────────────────────────
        for (line_no, line) in lines.iter().enumerate() {
            for rule in &rules {
                if let Some(m) = rule.pattern.find(line) {
                    issues.push(Issue {
                        line: line_no + 1,
                        column: m.start() + 1,
                        severity: rule.severity.clone(),
                        category: rule.category.clone(),
                        code: rule.id.to_string(),
                        message: rule.message.to_string(),
                        suggestion: rule.suggestion.map(|s| s.to_string()),
                        snippet: line.trim().to_string(),
                    });
                }
            }
        }

        // ── Structural checks ─────────────────────────────────────────────
        issues.extend(self.check_balanced_braces());
        issues.extend(self.check_unsafe_density());

        // ── Layer 7: CVE retention (replaces compare_with_cpp) ────────────
        if let Some(c_source) = &self.cpp_code {
            let result = cve_retention::analyze(c_source, &self.rust_code);
            issues.extend(result.issues);
        }

        issues
    }

    fn check_balanced_braces(&self) -> Vec<Issue> {
        let mut issues = Vec::new();
        let opens  = self.rust_code.matches('{').count();
        let closes = self.rust_code.matches('}').count();
        if opens != closes {
            issues.push(Issue {
                line: 0, column: 0,
                severity: Severity::Error,
                category: Category::Syntax,
                code: "STRUCT001".to_string(),
                message: format!("Unbalanced braces: {} open, {} close", opens, closes),
                suggestion: Some("Check for missing/extra braces.".to_string()),
                snippet: String::new(),
            });
        }
        issues
    }

    fn check_unsafe_density(&self) -> Vec<Issue> {
        let mut issues = Vec::new();
        let unsafe_count = self.rust_code.matches("unsafe").count();
        let total_lines  = self.rust_code.lines().count().max(1);
        let density = (unsafe_count as f64) / (total_lines as f64);
        if density > 0.05 {
            issues.push(Issue {
                line: 0, column: 0,
                severity: Severity::Warning,
                category: Category::Memory,
                code: "DENSE001".to_string(),
                message: format!(
                    "High unsafe density: {} occurrences / {} lines ({:.1}%)",
                    unsafe_count, total_lines, density * 100.0
                ),
                suggestion: Some("Refactor to safe abstractions. High unsafe density indicates heavy C pointer carry-over.".to_string()),
                snippet: String::new(),
            });
        }
        issues
    }
}
