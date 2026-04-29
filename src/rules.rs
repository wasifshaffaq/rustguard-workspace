use regex::Regex;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Error,
    Warning,
    Info,
    Hint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Category {
    Semantic,
    Syntax,
    Idiomatic,
    Memory,
    Concurrency,
    Performance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub line: usize,
    pub column: usize,
    pub severity: Severity,
    pub category: Category,
    pub code: String,
    pub message: String,
    pub suggestion: Option<String>,
    pub snippet: String,
}

pub struct Rule {
    pub id: &'static str,
    pub pattern: Regex,
    pub severity: Severity,
    pub category: Category,
    pub message: &'static str,
    pub suggestion: Option<&'static str>,
}

pub fn get_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "RAW001",
            pattern: Regex::new(r"\*mut\s+\w+|\*const\s+\w+").unwrap(),
            severity: Severity::Warning,
            category: Category::Memory,
            message: "Raw pointer detected — likely unsafe transpilation from C++ pointer.",
            suggestion: Some("Consider using &mut T, &T, Box<T>, Rc<T>, or Arc<T>."),
        },
        Rule {
            id: "RAW002",
            pattern: Regex::new(r"\bunsafe\s*\{").unwrap(),
            severity: Severity::Warning,
            category: Category::Memory,
            message: "Unsafe block found — verify if it can be made safe.",
            suggestion: Some("Encapsulate in safe abstractions or use Rust idioms."),
        },
        Rule {
            id: "MEM001",
            pattern: Regex::new(r"std::mem::transmute").unwrap(),
            severity: Severity::Error,
            category: Category::Memory,
            message: "transmute is extremely dangerous and rarely needed.",
            suggestion: Some("Use safe casts: as, From, TryFrom, or bytemuck."),
        },
        Rule {
            id: "IDIO001",
            pattern: Regex::new(r"\.unwrap\(\)").unwrap(),
            severity: Severity::Info,
            category: Category::Idiomatic,
            message: "unwrap() may panic — check for unhandled None/Err cases.",
            suggestion: Some("Use ? operator, match, or unwrap_or for safe handling."),
        },
        Rule {
            id: "IDIO002",
            pattern: Regex::new(r"\.clone\(\)").unwrap(),
            severity: Severity::Hint,
            category: Category::Performance,
            message: "Frequent clone() — possible C++ copy-semantic carry-over.",
            suggestion: Some("Consider borrowing (&T) instead of cloning."),
        },
        Rule {
            id: "IDIO004",
            pattern: Regex::new(r"for\s+\w+\s+in\s+0\.\.\w+\.len\(\)").unwrap(),
            severity: Severity::Hint,
            category: Category::Idiomatic,
            message: "C-style index loop detected.",
            suggestion: Some("Use iterator: for item in &collection or .iter().enumerate()."),
        },
        Rule {
            id: "SEM001",
            pattern: Regex::new(r"static\s+mut\s+").unwrap(),
            severity: Severity::Error,
            category: Category::Semantic,
            message: "static mut is unsafe and discouraged.",
            suggestion: Some("Use Mutex, RwLock, OnceCell, or atomic types."),
        },
        Rule {
            id: "SEM002",
            pattern: Regex::new(r"std::ptr::null|std::ptr::null_mut").unwrap(),
            severity: Severity::Warning,
            category: Category::Semantic,
            message: "Null pointer concept transferred from C++.",
            suggestion: Some("Use Option<T> instead of nullable pointers."),
        },
        Rule {
            id: "SYN001",
            pattern: Regex::new(r"//\s*TODO|//\s*FIXME|//\s*XXX").unwrap(),
            severity: Severity::Warning,
            category: Category::Syntax,
            message: "TODO/FIXME marker — likely incomplete transpilation.",
            suggestion: None,
        },
        Rule {
            id: "SYN002",
            pattern: Regex::new(r"unimplemented!|todo!").unwrap(),
            severity: Severity::Error,
            category: Category::Syntax,
            message: "Unimplemented placeholder from transpilation.",
            suggestion: Some("Provide proper implementation."),
        },
        Rule {
            id: "PERF001",
            pattern: Regex::new(r#"String::from\(\s*""\s*\)"#).unwrap(),
            severity: Severity::Hint,
            category: Category::Performance,
            message: "Empty String allocation.",
            suggestion: Some("Use String::new() instead."),
        },
    ]
}