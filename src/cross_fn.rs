/// cross_fn.rs
///
/// Gap filled: No cross-function semantic checks (pure line-based warnings)
///
/// Analyzes the whole file as a unit to detect:
/// 1. Unsafe functions called from safe public functions (unsafe propagation)
/// 2. Functions that return raw pointers (ownership escape)
/// 3. Public API surface that exposes raw pointer parameters (unsafe API leakage)
/// 4. Functions that create raw resources but have no corresponding cleanup function
/// 5. Recursive unsafe functions (stack overflow + unsafe = very dangerous)

use crate::rules::{Issue, Severity, Category};
use syn::{
    visit::Visit,
    File, ItemFn, Signature, ReturnType, Type, FnArg, Pat,
    Expr, ExprCall, ExprUnsafe,
};
use proc_macro2::Span;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
struct FnSummary {
    name: String,
    line: usize,
    is_unsafe: bool,
    is_pub: bool,
    returns_raw_ptr: bool,
    takes_raw_ptr: bool,
    calls: Vec<String>,            // functions this fn calls
    has_unsafe_block: bool,
    has_alloc: bool,               // calls Box::new, Vec::new, malloc-like
    is_recursive: bool,
}

pub struct CrossFnAnalyzer {
    pub issues: Vec<Issue>,
    summaries: HashMap<String, FnSummary>,
    current_fn: Option<String>,
}

impl CrossFnAnalyzer {
    pub fn new() -> Self {
        Self {
            issues: Vec::new(),
            summaries: HashMap::new(),
            current_fn: None,
        }
    }

    fn span_lc(span: Span) -> (usize, usize) {
        let s = span.start();
        (s.line, s.column + 1)
    }

    fn add(&mut self, line: usize, col: usize, code: &str,
           severity: Severity, msg: String, suggestion: String) {
        self.issues.push(Issue {
            line, column: col,
            severity,
            category: Category::Semantic,
            code: code.to_string(),
            message: msg,
            suggestion: Some(suggestion),
            snippet: String::new(),
        });
    }

    /// Second pass: analyze the collected summaries for cross-function issues
    fn analyze_summaries(&mut self) {
        let summaries: Vec<FnSummary> = self.summaries.values().cloned().collect();
        let unsafe_fns: HashSet<String> = summaries.iter()
            .filter(|s| s.is_unsafe || s.has_unsafe_block)
            .map(|s| s.name.clone())
            .collect();

        for s in &summaries {
            // 1. Public safe fn calls unsafe fn — unsafe propagation
            if s.is_pub && !s.is_unsafe {
                let unsafe_calls: Vec<&String> = s.calls.iter()
                    .filter(|c| unsafe_fns.contains(*c))
                    .collect();
                if !unsafe_calls.is_empty() {
                    self.add(
                        s.line, 1,
                        "CROSS_001",
                        Severity::Error,
                        format!(
                            "Public safe fn '{}' calls unsafe fn(s) [{}] — unsound API, callers assume safety",
                            s.name,
                            unsafe_calls.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                        ),
                        "Either mark '{}' as unsafe, or wrap the unsafe calls in a safety invariant check and document the invariants.".to_string(),
                    );
                }
            }

            // 2. Public fn returns raw pointer — ownership escape
            if s.is_pub && s.returns_raw_ptr {
                self.add(
                    s.line, 1,
                    "CROSS_002",
                    Severity::Error,
                    format!(
                        "Public fn '{}' returns a raw pointer — ownership escapes to caller with no safety contract",
                        s.name
                    ),
                    "Return Box<T>, Arc<T>, or a reference instead of a raw pointer. If FFI is required, document the ownership transfer.".to_string(),
                );
            }

            // 3. Public fn takes raw pointer parameter — unsafe API leakage
            if s.is_pub && s.takes_raw_ptr && !s.is_unsafe {
                self.add(
                    s.line, 1,
                    "CROSS_003",
                    Severity::Warning,
                    format!(
                        "Public safe fn '{}' accepts a raw pointer — callers can pass any address with no safety check",
                        s.name
                    ),
                    "Accept &T or &mut T instead of *const/*mut T. If raw pointer is needed for FFI, mark the function unsafe.".to_string(),
                );
            }

            // 4. Recursive unsafe function — stack overflow risk amplified by unsafe
            if s.is_recursive && s.is_unsafe {
                self.add(
                    s.line, 1,
                    "CROSS_004",
                    Severity::Error,
                    format!(
                        "Fn '{}' is both recursive and unsafe — stack overflow in unsafe context causes undefined behavior",
                        s.name
                    ),
                    "Convert to iterative form, or add a depth limit guard before the unsafe block.".to_string(),
                );
            }

            // 5. Fn allocates but no paired deallocator fn detected
            if s.has_alloc && s.returns_raw_ptr {
                let cleanup_name_patterns = [
                    format!("free_{}", s.name),
                    format!("destroy_{}", s.name),
                    format!("drop_{}", s.name),
                    format!("{}_free", s.name),
                    format!("{}_destroy", s.name),
                ];
                let has_cleanup = cleanup_name_patterns.iter()
                    .any(|n| self.summaries.contains_key(n));
                if !has_cleanup {
                    self.add(
                        s.line, 1,
                        "CROSS_005",
                        Severity::Warning,
                        format!(
                            "Fn '{}' allocates and returns raw pointer but no cleanup function detected — possible memory leak from C pattern",
                            s.name
                        ),
                        "Provide a corresponding free_X() function or return Box<T> which auto-drops.".to_string(),
                    );
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for CrossFnAnalyzer {

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let name = node.sig.ident.to_string();
        let (line, _) = Self::span_lc(node.sig.ident.span());

        let is_unsafe = node.sig.unsafety.is_some();
        let is_pub = matches!(node.vis, syn::Visibility::Public(_));

        let returns_raw_ptr = match &node.sig.output {
            ReturnType::Type(_, ty) => matches!(ty.as_ref(), Type::Ptr(_)),
            _ => false,
        };

        let takes_raw_ptr = node.sig.inputs.iter().any(|arg| {
            if let FnArg::Typed(pt) = arg {
                matches!(pt.ty.as_ref(), Type::Ptr(_))
            } else { false }
        });

        let has_unsafe_block = contains_unsafe_block(&node.block);

        // Collect calls made by this function
        let mut call_collector = CallCollector::new();
        call_collector.visit_block(&node.block);
        let calls = call_collector.calls;

        // Recursive if it calls itself
        let is_recursive = calls.contains(&name);

        // Alloc detection
        let has_alloc = calls.iter().any(|c| {
            matches!(c.as_str(), "from_raw" | "into_raw" | "into_raw_parts")
            || c.contains("alloc")
        });

        let summary = FnSummary {
            name: name.clone(),
            line,
            is_unsafe,
            is_pub,
            returns_raw_ptr,
            takes_raw_ptr,
            calls,
            has_unsafe_block,
            has_alloc,
            is_recursive,
        };

        self.summaries.insert(name.clone(), summary);
        self.current_fn = Some(name);

        syn::visit::visit_item_fn(self, node);

        self.current_fn = None;
    }
}

// ── Helper: collect function call names ──────────────────────────────────────
struct CallCollector {
    calls: Vec<String>,
}

impl CallCollector {
    fn new() -> Self { Self { calls: Vec::new() } }
}

impl<'ast> Visit<'ast> for CallCollector {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(p) = node.func.as_ref() {
            let name = p.path.segments.last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            if !name.is_empty() {
                self.calls.push(name);
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

fn contains_unsafe_block(block: &syn::Block) -> bool {
    struct Finder(bool);
    impl<'a> Visit<'a> for Finder {
        fn visit_expr_unsafe(&mut self, _: &'a ExprUnsafe) { self.0 = true; }
    }
    let mut f = Finder(false);
    f.visit_block(block);
    f.0
}

// ── Public entry point ────────────────────────────────────────────────────────
pub fn analyze(source: &str) -> Result<Vec<Issue>, syn::Error> {
    let file: File = syn::parse_file(source)?;
    let mut analyzer = CrossFnAnalyzer::new();
    analyzer.visit_file(&file);
    // Run the second-pass cross-function analysis
    analyzer.analyze_summaries();
    Ok(analyzer.issues)
}
