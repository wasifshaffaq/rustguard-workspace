/// cve_retention.rs
///
/// Gap filled: C-source semantic comparison (VRR metric, Wu et al. 2025 base paper)
/// 
/// Goes far beyond the old compare_with_cpp() which only counted function signatures.
/// 
/// This module:
/// 1. Detects dangerous C patterns in the C source (buffer overflows, use-after-free, etc.)
/// 2. Checks whether the Rust translation contains equivalent dangerous patterns
/// 3. Produces per-CVE-class retention findings
/// 4. Computes the VRR (Vulnerability Retention Rate) for Objective 3

use crate::rules::{Issue, Severity, Category};
use regex::Regex;

#[derive(Debug, Clone)]
pub struct CvePattern {
    pub cwe: &'static str,       // CWE identifier
    pub name: &'static str,
    pub c_pattern: &'static str, // regex for C source
    pub rust_danger: &'static str, // regex for dangerous Rust equivalent
    pub rust_safe: &'static str,   // regex for SAFE Rust equivalent (if present, suppresses)
    pub severity: Severity,
    pub message: &'static str,
    pub suggestion: &'static str,
}

pub fn get_cve_patterns() -> Vec<CvePattern> {
    vec![
        CvePattern {
            cwe: "CWE-120",
            name: "Buffer overflow (strcpy/gets)",
            c_pattern: r"strcpy\s*\(|gets\s*\(|strcat\s*\(",
            rust_danger: r"ptr::copy|ptr::copy_nonoverlapping|\.get_unchecked",
            rust_safe: r"\.copy_from_slice|String::from|\.push_str",
            severity: Severity::Error,
            message: "Buffer overflow pattern (strcpy/gets in C) — check Rust uses bounded copy, not ptr::copy",
            suggestion: "Use slice::copy_from_slice() or String::push_str() instead of raw ptr::copy.",
        },
        CvePattern {
            cwe: "CWE-416",
            name: "Use-after-free",
            c_pattern: r"\bfree\s*\([^)]+\).{0,100}\1",  // free(x) ... x used again
            rust_danger: r"Box::from_raw|ptr::drop_in_place",
            rust_safe: r"drop\(|ManuallyDrop",
            severity: Severity::Error,
            message: "Use-after-free pattern (free() in C) — Rust Box::from_raw carries same risk if ptr reused",
            suggestion: "Set pointer to null after Box::from_raw drop, or use ManuallyDrop<T>.",
        },
        CvePattern {
            cwe: "CWE-415",
            name: "Double free",
            c_pattern: r"\bfree\s*\(",
            rust_danger: r"Box::from_raw.{0,200}Box::from_raw",
            rust_safe: r"ManuallyDrop|Option.*take\(\)",
            severity: Severity::Error,
            message: "Double-free risk — C uses multiple free() calls; check Rust does not Box::from_raw twice",
            suggestion: "Track raw pointer lifecycle with Option<*mut T>; set to None after first Box::from_raw.",
        },
        CvePattern {
            cwe: "CWE-476",
            name: "Null pointer dereference",
            c_pattern: r"NULL|nullptr|\bif\s*\(\s*\w+\s*\)",  // C null checks
            rust_danger: r"\.unwrap\(\)|std::ptr::null|as \*mut|as \*const",
            rust_safe: r"\.is_null\(\)|Option::|NonNull",
            severity: Severity::Error,
            message: "Null pointer pattern in C source — Rust translation uses raw ptr or unwrap() without null check",
            suggestion: "Use Option<NonNull<T>> or check .is_null() before any raw pointer dereference.",
        },
        CvePattern {
            cwe: "CWE-190",
            name: "Integer overflow",
            c_pattern: r"\bint\s+\w+\s*=|unsigned\s+\w+\s*=",
            rust_danger: r"as\s+i32|as\s+u32|as\s+i16|as\s+u16|as\s+i8|as\s+u8",
            rust_safe: r"\.checked_add|\.checked_mul|\.saturating|TryFrom|TryInto",
            severity: Severity::Warning,
            message: "Integer type pattern from C — Rust 'as' cast silently truncates, same as C undefined behavior",
            suggestion: "Replace 'as i32' with i32::try_from(val)? or use .checked_add() for arithmetic.",
        },
        CvePattern {
            cwe: "CWE-125",
            name: "Out-of-bounds read",
            c_pattern: r"\w+\s*\[\s*\w+\s*\]",  // C array indexing
            rust_danger: r"\.get_unchecked\(|ptr::read\b",
            rust_safe: r"\.get\(|\.iter\(\)|for.*in",
            severity: Severity::Error,
            message: "Out-of-bounds read pattern — C array indexing replaced by unchecked Rust access",
            suggestion: "Use slice.get(i) which returns Option<T>, or iterator-based access.",
        },
        CvePattern {
            cwe: "CWE-134",
            name: "Format string injection",
            c_pattern: r"printf\s*\(\s*\w+|sprintf\s*\(",
            rust_danger: r#"format!\s*\(\s*\w+[^,\)"]+\)|write!\s*\(\w+,\s*\w+[^,\)"]+\)"#,
            rust_safe: r#"format!\s*\(\s*\""#,
            severity: Severity::Warning,
            message: "Format string pattern from C printf — check Rust format! uses a literal string, not a variable",
            suggestion: "Always use string literals in format!(): format!(\"{}\", user_input) not format!(user_input).",
        },
        CvePattern {
            cwe: "CWE-401",
            name: "Memory leak (malloc without free)",
            c_pattern: r"\bmalloc\s*\(|\bcalloc\s*\(|\brealloc\s*\(",
            rust_danger: r"Box::into_raw|Vec::into_raw_parts|ManuallyDrop::new",
            rust_safe: r"Box::new|Vec::new|Arc::new",
            severity: Severity::Warning,
            message: "Memory allocation pattern from C malloc — Rust Box::into_raw leaks memory if not re-boxed",
            suggestion: "Prefer Box<T> or Vec<T> which auto-drop. If leaking intentionally, document it.",
        },
        CvePattern {
            cwe: "CWE-362",
            name: "Race condition",
            c_pattern: r"pthread_|mutex_lock|sem_wait",
            rust_danger: r"static\s+mut\s+|Mutex.*unwrap\(\)|RwLock.*unwrap\(\)",
            rust_safe: r"std::sync::Mutex|parking_lot|OnceLock",
            severity: Severity::Warning,
            message: "Concurrency pattern from C threading — check Rust avoids static mut and properly handles Mutex poisoning",
            suggestion: "Use std::sync::Mutex<T>. Handle lock().unwrap() with proper error handling for poisoned locks.",
        },
    ]
}

#[derive(Debug)]
pub struct RetentionResult {
    pub issues: Vec<Issue>,
    pub vrr: usize,             // count of retained vulnerabilities
    pub c_patterns_found: usize,
    pub safe_replacements: usize,
}

pub fn analyze(c_source: &str, rust_source: &str) -> RetentionResult {
    let patterns = get_cve_patterns();
    let mut issues = Vec::new();
    let mut vrr = 0usize;
    let mut c_patterns_found = 0usize;
    let mut safe_replacements = 0usize;

    for pat in &patterns {
        let c_re = match Regex::new(pat.c_pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let rust_danger_re = match Regex::new(pat.rust_danger) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let rust_safe_re = match Regex::new(pat.rust_safe) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Does C source contain this vulnerability class?
        if !c_re.is_match(c_source) { continue; }
        c_patterns_found += 1;

        let rust_has_danger = rust_danger_re.is_match(rust_source);
        let rust_has_safe   = rust_safe_re.is_match(rust_source);

        if rust_has_danger && !rust_has_safe {
            // Vulnerability retained — worst case
            vrr += 1;

            // Find the line in Rust source where the dangerous pattern appears
            let line_no = find_pattern_line(rust_source, pat.rust_danger)
                .unwrap_or(0);

            issues.push(Issue {
                line: line_no,
                column: 1,
                severity: pat.severity.clone(),
                category: Category::Semantic,
                code: format!("VRR_{}", pat.cwe.replace('-', "_")),
                message: format!(
                    "[{}] {} — vulnerability retained from C source into Rust translation (Wu et al. 2025)",
                    pat.cwe, pat.message
                ),
                suggestion: Some(pat.suggestion.to_string()),
                snippet: String::new(),
            });
        } else if rust_has_safe {
            safe_replacements += 1;
            // Safe replacement present — still inform but as info
            issues.push(Issue {
                line: 0, column: 1,
                severity: Severity::Info,
                category: Category::Semantic,
                code: format!("VRR_{}_SAFE", pat.cwe.replace('-', "_")),
                message: format!(
                    "[{}] {} — C pattern found, safe Rust replacement detected ✓",
                    pat.cwe, pat.name
                ),
                suggestion: None,
                snippet: String::new(),
            });
        } else if rust_has_danger {
            // Dangerous pattern in Rust but C pattern also present — mark
            vrr += 1;
            let line_no = find_pattern_line(rust_source, pat.rust_danger).unwrap_or(0);
            issues.push(Issue {
                line: line_no, column: 1,
                severity: pat.severity.clone(),
                category: Category::Semantic,
                code: format!("VRR_{}", pat.cwe.replace('-', "_")),
                message: format!(
                    "[{}] {} — dangerous pattern present in Rust (no safe replacement found)",
                    pat.cwe, pat.message
                ),
                suggestion: Some(pat.suggestion.to_string()),
                snippet: String::new(),
            });
        }
    }

    // Function count delta (kept from original, but now as context not primary metric)
    let c_fn_count = Regex::new(r"\b\w[\w\s]*\s+\w+\s*\([^)]*\)\s*\{")
        .map(|r| r.find_iter(c_source).count())
        .unwrap_or(0);
    let rust_fn_count = rust_source.matches("fn ").count();

    if c_fn_count > 0 && rust_fn_count < c_fn_count / 2 {
        issues.push(Issue {
            line: 0, column: 0,
            severity: Severity::Warning,
            category: Category::Semantic,
            code: "VRR_COVERAGE".to_string(),
            message: format!(
                "Translation coverage: C has ~{} functions, Rust has {} — {} functions may be untranspiled",
                c_fn_count, rust_fn_count, c_fn_count - rust_fn_count
            ),
            suggestion: Some("Review which C functions were omitted. Missing functions may include critical security logic.".to_string()),
            snippet: String::new(),
        });
    }

    RetentionResult { issues, vrr, c_patterns_found, safe_replacements }
}

fn find_pattern_line(source: &str, pattern: &str) -> Option<usize> {
    let re = Regex::new(pattern).ok()?;
    for (line_no, line) in source.lines().enumerate() {
        if re.is_match(line) {
            return Some(line_no + 1);
        }
    }
    None
}
