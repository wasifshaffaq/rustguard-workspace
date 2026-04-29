use crate::rules::{get_rules, Issue, Severity, Category};

pub struct Analyzer {
    rust_code: String,
    cpp_code: Option<String>,
}

impl Analyzer {
    pub fn new(rust_code: String, cpp_code: Option<String>) -> Self {
        Self { rust_code, cpp_code }
    }

    pub fn run(&mut self) -> Vec<Issue> {
        let mut issues = Vec::new();
        let rules = get_rules();
        let lines: Vec<&str> = self.rust_code.lines().collect();

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

        issues.extend(self.check_balanced_braces());
        issues.extend(self.check_unsafe_density());
        if self.cpp_code.is_some() {
            issues.extend(self.compare_with_cpp());
        }
        issues
    }

    fn check_balanced_braces(&self) -> Vec<Issue> {
        let mut issues = Vec::new();
        let opens = self.rust_code.matches('{').count();
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
        let total_lines = self.rust_code.lines().count().max(1);
        let density = (unsafe_count as f64) / (total_lines as f64);
        if density > 0.05 {
            issues.push(Issue {
                line: 0, column: 0,
                severity: Severity::Warning,
                category: Category::Memory,
                code: "DENSE001".to_string(),
                message: format!("High unsafe density: {} / {} lines ({:.1}%)",
                    unsafe_count, total_lines, density * 100.0),
                suggestion: Some("Refactor to safe abstractions.".to_string()),
                snippet: String::new(),
            });
        }
        issues
    }

    fn compare_with_cpp(&self) -> Vec<Issue> {
        let mut issues = Vec::new();
        let cpp = self.cpp_code.as_ref().unwrap();
        let cpp_fns = regex::Regex::new(r"\b\w+\s+\w+\s*\([^)]*\)\s*\{").unwrap()
            .find_iter(cpp).count();
        let rust_fns = self.rust_code.matches("fn ").count();
        if cpp_fns > 0 && rust_fns < cpp_fns / 2 {
            issues.push(Issue {
                line: 0, column: 0,
                severity: Severity::Warning,
                category: Category::Semantic,
                code: "CMP001".to_string(),
                message: format!("Function count mismatch: C++ ~{}, Rust {}", cpp_fns, rust_fns),
                suggestion: Some("Some functions may not have been transpiled.".to_string()),
                snippet: String::new(),
            });
        }
        issues
    }
}