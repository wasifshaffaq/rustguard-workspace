/// rules.rs — updated with full rule set covering all survey gaps

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
    Aliasing,      // NEW: Sub-Gap 4 [46][47]
    Ownership,     // NEW: Sub-Gap 3 ownership graph
    LlmHallucination, // NEW: LLM bug taxonomy [33][14]
    CveRetention,  // NEW: Wu et al. 2025 base paper
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
        // ── EXISTING RULES (unchanged) ────────────────────────────────────

        Rule {
            id: "RAW001",
            pattern: Regex::new(r"\*mut\s+\w+|\*const\s+\w+").unwrap(),
            severity: Severity::Warning,
            category: Category::Memory,
            message: "Raw pointer detected — likely unsafe transpilation from C pointer.",
            suggestion: Some("Consider using &mut T, &T, Box<T>, Rc<T>, or Arc<T>."),
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
            message: "Null pointer concept transferred from C/C++.",
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

        // ── NEW: ALIASING RULES (Sub-Gap 4) ──────────────────────────────

        Rule {
            id: "ALIAS001",
            pattern: Regex::new(r"union\s+\w+\s*\{").unwrap(),
            severity: Severity::Error,
            category: Category::Aliasing,
            message: "C-style union in Rust — unsafe memory layout, no discriminant safety [47].",
            suggestion: Some("Replace with a Rust enum (tagged union). Each variant holds its data safely."),
        },
        Rule {
            id: "ALIAS002",
            pattern: Regex::new(r"\bas\s+\*mut\s+\w+").unwrap(),
            severity: Severity::Warning,
            category: Category::Aliasing,
            message: "Pointer cast to *mut — aliasing artifact from C pointer translation [46].",
            suggestion: Some("Use NonNull<T> or Arc<Mutex<T>> to express ownership semantics."),
        },
        Rule {
            id: "ALIAS003",
            pattern: Regex::new(r"std::ptr::read\b|std::ptr::write\b").unwrap(),
            severity: Severity::Warning,
            category: Category::Aliasing,
            message: "ptr::read/write — raw memory access bypasses aliasing rules.",
            suggestion: Some("Use safe slice operations or abstract behind a checked wrapper."),
        },

        // ── NEW: LLM HALLUCINATION RULES (Sub-Gap 3) ─────────────────────

        Rule {
            id: "LLM_PAT001",
            pattern: Regex::new(r"'static\b").unwrap(),
            severity: Severity::Warning,
            category: Category::LlmHallucination,
            message: "'static lifetime — LLMs frequently over-apply this; verify the data truly lives forever.",
            suggestion: Some("Replace 'static with a named lifetime parameter tied to the enclosing scope."),
        },
        Rule {
            id: "LLM_PAT002",
            pattern: Regex::new(r"\.get_unchecked\(|\.get_unchecked_mut\(").unwrap(),
            severity: Severity::Error,
            category: Category::LlmHallucination,
            message: "get_unchecked() — LLMs generate this as a direct translation of C array[i]; bounds check bypassed.",
            suggestion: Some("Use .get(i) which returns Option<T>, or .get(i).unwrap_or_default()."),
        },
        Rule {
            id: "LLM_PAT003",
            pattern: Regex::new(r"Box::from_raw\s*\(").unwrap(),
            severity: Severity::Error,
            category: Category::LlmHallucination,
            message: "Box::from_raw — LLM-generated code commonly uses this incorrectly, causing double-free or use-after-free.",
            suggestion: Some("Only call Box::from_raw on pointers created by Box::into_raw. Never call twice on same pointer."),
        },
        Rule {
            id: "LLM_PAT004",
            pattern: Regex::new(r"ptr::drop_in_place\s*\(").unwrap(),
            severity: Severity::Error,
            category: Category::LlmHallucination,
            message: "ptr::drop_in_place — direct C destructor translation; extremely dangerous if called on invalid memory.",
            suggestion: Some("Use Box<T> drop semantics instead. Only call drop_in_place if you are certain the pointer is valid."),
        },
        Rule {
            id: "LLM_PAT005",
            pattern: Regex::new(r"as\s+\*mut\s+\w+\s*;|as\s+\*const\s+\w+\s*;").unwrap(),
            severity: Severity::Warning,
            category: Category::LlmHallucination,
            message: "Bare pointer cast as statement — LLM likely translated a C cast idiom literally.",
            suggestion: Some("Pointer casts should be used inside unsafe blocks with documented safety invariants."),
        },

        // ── NEW: CVE RETENTION PATTERN RULES (Wu et al. 2025) ────────────

        Rule {
            id: "CVE_BUF001",
            pattern: Regex::new(r"ptr::copy\b|ptr::copy_nonoverlapping\b").unwrap(),
            severity: Severity::Error,
            category: Category::CveRetention,
            message: "ptr::copy — direct translation of memcpy/strcpy; no bounds check, CWE-120 retained.",
            suggestion: Some("Use slice::copy_from_slice() which panics on length mismatch instead of corrupting memory."),
        },
        Rule {
            id: "CVE_INT001",
            pattern: Regex::new(r"\bas\s+i8\b|\bas\s+u8\b|\bas\s+i16\b|\bas\s+u16\b").unwrap(),
            severity: Severity::Warning,
            category: Category::CveRetention,
            message: "Narrowing cast (as i8/u8/i16/u16) — silent truncation, same behavior as C integer overflow (CWE-190).",
            suggestion: Some("Use i8::try_from(val)? or .checked_cast() to detect overflow instead of silent truncation."),
        },
        Rule {
            id: "CVE_FMT001",
            pattern: Regex::new(r#"format!\s*\(\s*[a-zA-Z_]\w*\s*[,\)]"#).unwrap(),
            severity: Severity::Warning,
            category: Category::CveRetention,
            message: "format!() with non-literal first arg — possible format string injection (CWE-134 retained from C printf).",
            suggestion: Some("Always use a string literal: format!(\"{}\", variable) not format!(variable)."),
        },

        // ── NEW: CONCURRENCY RULES ────────────────────────────────────────

        Rule {
            id: "CONC001",
            pattern: Regex::new(r"Mutex.*\.unwrap\(\)|RwLock.*\.unwrap\(\)").unwrap(),
            severity: Severity::Warning,
            category: Category::Concurrency,
            message: "Mutex/RwLock .unwrap() — panics if the lock is poisoned (thread panicked while holding it).",
            suggestion: Some("Use .lock().unwrap_or_else(|e| e.into_inner()) to handle poisoned locks gracefully."),
        },
        Rule {
            id: "CONC002",
            pattern: Regex::new(r"Arc::clone\(&\w+\)").unwrap(),
            severity: Severity::Hint,
            category: Category::Concurrency,
            message: "Arc::clone — verify this is shared ownership, not a C-style reference count idiom.",
            suggestion: Some("Ensure the Arc is necessary; for single-threaded use, Rc<T> is cheaper."),
        },
    ]
}
