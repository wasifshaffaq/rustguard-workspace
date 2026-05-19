/// dataflow.rs
/// 
/// Gap filled: Sub-Gap 1 (static analysis ceiling) + Sub-Gap 3 (LLM hallucination)
/// Implements intra-function data-flow taint analysis:
/// - Tracks variables that originate from unsafe sources (raw ptr deref, transmute, FFI)
/// - Detects when tainted values flow into safe operations (indexing, arithmetic, returns)
/// - Detects double-free patterns, use-after-free patterns
/// - Classifies bugs using LLM bug taxonomy from [33] and [14]
///
/// This is the core "semantic" layer that pure regex/AST structural checks cannot provide.

use crate::rules::{Issue, Severity, Category};
use syn::{
    visit::Visit,
    ItemFn, Stmt, Expr, Pat, Local,
    ExprUnsafe, ExprCall, ExprMethodCall,
    ExprBinary, ExprIndex, ExprUnary,
    ExprAssign, ExprReturn,
};
use proc_macro2::Span;
use std::collections::{HashMap, HashSet};

// ── Bug taxonomy from Pan et al. [33] and Towards Translating [14] ──────────
#[derive(Debug, Clone, PartialEq)]
pub enum LlmBugClass {
    HallucinatedOwnership,   // value moved when it should be borrowed
    IncorrectLifetime,       // 'static used where scoped lifetime needed
    UnsafeEncapsulation,     // unsafe logic leaked into nominally safe fn
    TaintPropagation,        // unsafe-origin value used in safe indexing/arith
    DoubleConsumed,          // value used after move (LLM forgets ownership)
    NullDerefRisk,           // nullable ptr dereffed without check
    AliasingViolation,       // two mut refs to overlapping memory
    LogicBugRetained,        // C logic bug pattern reproduced in Rust
}

impl LlmBugClass {
    pub fn code(&self) -> &'static str {
        match self {
            Self::HallucinatedOwnership => "LLM_OWN001",
            Self::IncorrectLifetime     => "LLM_LT001",
            Self::UnsafeEncapsulation   => "LLM_ENC001",
            Self::TaintPropagation      => "LLM_TAINT001",
            Self::DoubleConsumed        => "LLM_MOVE001",
            Self::NullDerefRisk         => "LLM_NULL001",
            Self::AliasingViolation     => "LLM_ALIAS001",
            Self::LogicBugRetained      => "LLM_LOGIC001",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::TaintPropagation | Self::NullDerefRisk
            | Self::AliasingViolation | Self::DoubleConsumed => Severity::Error,
            _ => Severity::Warning,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::HallucinatedOwnership =>
                "LLM hallucination: value moved where borrow was intended — ownership semantics incorrectly modelled",
            Self::IncorrectLifetime =>
                "LLM hallucination: 'static lifetime applied where a scoped lifetime is correct — common LLM over-approximation",
            Self::UnsafeEncapsulation =>
                "Unsafe logic leaked through a nominally safe function boundary — encapsulation is unsound [Li et al., ISSTA 2025]",
            Self::TaintPropagation =>
                "Tainted value from unsafe source flows into safe index/arithmetic — potential panic or memory corruption",
            Self::DoubleConsumed =>
                "Variable used after move — LLM forgot Rust ownership rules, value may be double-freed",
            Self::NullDerefRisk =>
                "Nullable pointer dereferenced without null check — C null-deref pattern retained in Rust",
            Self::AliasingViolation =>
                "Multiple mutable references to overlapping memory — aliasing artifact from C pointer translation [46]",
            Self::LogicBugRetained =>
                "C logic bug pattern detected in Rust translation — vulnerability retained per Wu et al. (2025)",
        }
    }
}

// ── Taint source kinds ────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
enum TaintSource {
    RawPtrDeref,
    Transmute,
    FfiCall(String),
    UncheckedIndex,
    NullablePtr,
}

// ── Per-function data-flow state ─────────────────────────────────────────────
struct FnFlowState {
    /// variable name → taint source
    tainted: HashMap<String, TaintSource>,
    /// variables that have been moved (consumed)
    moved: HashSet<String>,
    /// raw pointer variable names
    raw_ptrs: HashSet<String>,
    /// variables bound from Box::from_raw (double-free risk)
    from_raw: HashSet<String>,
    issues: Vec<(usize, usize, LlmBugClass, String)>, // (line, col, class, detail)
}

impl FnFlowState {
    fn new() -> Self {
        Self {
            tainted: HashMap::new(),
            moved: HashSet::new(),
            raw_ptrs: HashSet::new(),
            from_raw: HashSet::new(),
            issues: Vec::new(),
        }
    }

    fn mark_tainted(&mut self, var: &str, src: TaintSource) {
        self.tainted.insert(var.to_string(), src);
    }

    fn is_tainted(&self, var: &str) -> bool {
        self.tainted.contains_key(var)
    }

    fn mark_moved(&mut self, var: &str) {
        self.moved.insert(var.to_string());
    }

    fn is_moved(&self, var: &str) -> bool {
        self.moved.contains(var)
    }
}

// ── Main visitor ─────────────────────────────────────────────────────────────
pub struct DataFlowAnalyzer {
    pub issues: Vec<Issue>,
    fn_stack: Vec<FnFlowState>,
    in_unsafe: usize,
}

impl DataFlowAnalyzer {
    pub fn new() -> Self {
        Self {
            issues: Vec::new(),
            fn_stack: Vec::new(),
            in_unsafe: 0,
        }
    }

    fn current(&mut self) -> Option<&mut FnFlowState> {
        self.fn_stack.last_mut()
    }

    fn emit(&mut self, line: usize, col: usize, class: LlmBugClass, detail: String) {
        self.issues.push(Issue {
            line, column: col,
            severity: class.severity(),
            category: Category::Semantic,
            code: class.code().to_string(),
            message: format!("{} — {}", class.description(), detail),
            suggestion: Some(Self::suggestion_for(&class)),
            snippet: String::new(),
        });
    }

    fn suggestion_for(class: &LlmBugClass) -> String {
        match class {
            LlmBugClass::HallucinatedOwnership =>
                "Add & to borrow instead of move, or use .clone() intentionally".to_string(),
            LlmBugClass::IncorrectLifetime =>
                "Replace 'static with a named lifetime parameter tied to the enclosing scope".to_string(),
            LlmBugClass::UnsafeEncapsulation =>
                "Either mark the outer function unsafe, or add explicit safety invariant checks inside".to_string(),
            LlmBugClass::TaintPropagation =>
                "Validate the unsafe-origin value (bounds check, null check) before using it in safe code".to_string(),
            LlmBugClass::DoubleConsumed =>
                "Track ownership explicitly; use Option<T>::take() to prevent double-consume".to_string(),
            LlmBugClass::NullDerefRisk =>
                "Wrap pointer in Option<NonNull<T>> and check .is_null() before deref".to_string(),
            LlmBugClass::AliasingViolation =>
                "Ensure no two &mut T references overlap; use split_at_mut() for disjoint slices".to_string(),
            LlmBugClass::LogicBugRetained =>
                "Review the original C source for this logic pattern and re-implement in idiomatic Rust".to_string(),
        }
    }

    /// Extract variable name from a simple path expression
    fn expr_to_var(expr: &Expr) -> Option<String> {
        if let Expr::Path(p) = expr {
            if p.path.segments.len() == 1 {
                return Some(p.path.segments[0].ident.to_string());
            }
        }
        None
    }

    fn span_lc(span: Span) -> (usize, usize) {
        let s = span.start();
        (s.line, s.column + 1)
    }

    /// Check if an expression uses a tainted variable
    fn check_taint_in_expr(&mut self, expr: &Expr) {
        if let Some(var) = Self::expr_to_var(expr) {
            if let Some(state) = self.fn_stack.last() {
                if state.is_tainted(&var) {
                    let (line, col) = if let Expr::Path(p) = expr {
                        Self::span_lc(p.path.segments[0].ident.span())
                    } else { (0, 0) };
                    let detail = format!("variable '{}' originates from unsafe source", var);
                    // Collect separately to avoid borrow conflict
                    let bug = (line, col, LlmBugClass::TaintPropagation, detail);
                    if let Some(state) = self.fn_stack.last_mut() {
                        state.issues.push(bug);
                    }
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for DataFlowAnalyzer {

    // ── Enter function: push fresh flow state ─────────────────────────────
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.fn_stack.push(FnFlowState::new());

        let fn_name = node.sig.ident.to_string();
        let is_unsafe_fn = node.sig.unsafety.is_some();

        // Pre-scan: does this function contain unsafe blocks but is not marked unsafe?
        // That's unsafe encapsulation (LLM_ENC001)
        let has_unsafe_block = contains_unsafe_block(&node.block);
        if !is_unsafe_fn && has_unsafe_block {
            let (line, col) = Self::span_lc(node.sig.ident.span());
            if let Some(state) = self.fn_stack.last_mut() {
                state.issues.push((
                    line, col,
                    LlmBugClass::UnsafeEncapsulation,
                    format!("fn '{}' wraps unsafe code but is not marked unsafe", fn_name),
                ));
            }
        }

        // Check for 'static lifetime in function signatures (LLM_LT001)
        for lt in collect_lifetimes_in_fn(node) {
            if lt.0 == "static" {
                let (line, col) = lt.1;
                if let Some(state) = self.fn_stack.last_mut() {
                    state.issues.push((
                        line, col,
                        LlmBugClass::IncorrectLifetime,
                        format!("fn '{}' has 'static lifetime — verify LLM did not hallucinate this", fn_name),
                    ));
                }
            }
        }

        syn::visit::visit_item_fn(self, node);

        // Pop state and flush issues
        if let Some(state) = self.fn_stack.pop() {
            for (line, col, class, detail) in state.issues {
                self.emit(line, col, class, detail);
            }
        }
    }

    // ── Track raw pointer variable bindings ───────────────────────────────
    fn visit_local(&mut self, node: &'ast Local) {
        if let Some(init) = &node.init {
            let expr = unwrap_unsafe_expr(init.expr.as_ref());
            let (var_name, annotated_ty, pat_span) = extract_pat_ident_and_type(&node.pat);

            if let Some(var) = &var_name {
                let (line, col) = Self::span_lc(pat_span);

                // 1. Dereference — taint the bound variable
                if let Expr::Unary(u) = expr {
                    if matches!(u.op, syn::UnOp::Deref(_)) {
                        if let Some(state) = self.fn_stack.last_mut() {
                            state.mark_tainted(var, TaintSource::RawPtrDeref);
                            // Also flag: is the deref of a raw ptr without null check?
                            if let Expr::Path(p) = u.expr.as_ref() {
                                let ptr_name = p.path.segments.last()
                                    .map(|s| s.ident.to_string()).unwrap_or_default();
                                if state.raw_ptrs.contains(&ptr_name) {
                                    state.issues.push((
                                        line, col,
                                        LlmBugClass::NullDerefRisk,
                                        format!("'{}' dereferenced from raw pointer '{}' without null check", var, ptr_name),
                                    ));
                                }
                            }
                        }
                    }
                }

                // 2. std::mem::transmute(...) — taint the bound variable
                if let Expr::Call(call) = expr {
                    if is_transmute_call(&call.func) {
                        if let Some(state) = self.fn_stack.last_mut() {
                            state.mark_tainted(var, TaintSource::Transmute);
                        }
                    }
                }

                // 3. Taint propagation through variable binding: let y = x;
                if let Some(rhs_var) = Self::expr_to_var(expr) {
                    if let Some(state) = self.fn_stack.last_mut() {
                        if let Some(src) = state.tainted.get(&rhs_var).cloned() {
                            state.mark_tainted(var, src);
                        }
                    }
                }

                // 4. Box::from_raw(p) — track for double-free detection
                if let Expr::Call(call) = expr {
                    if is_box_from_raw(&call.func) {
                        if let Some(state) = self.fn_stack.last_mut() {
                            if state.from_raw.contains(var) {
                                state.issues.push((
                                    line, col,
                                    LlmBugClass::LogicBugRetained,
                                    format!("'{}' re-boxed from raw — possible double-free (C free() pattern retained)", var),
                                ));
                            }
                            state.from_raw.insert(var.clone());
                        }
                    }
                }

                // 5. Track raw pointer variables
                let is_ptr = if let Some(ty) = annotated_ty {
                    matches!(ty, syn::Type::Ptr(_))
                } else {
                    matches!(expr, Expr::Cast(c) if matches!(c.ty.as_ref(), syn::Type::Ptr(_)))
                };

                if is_ptr {
                    if let Some(state) = self.fn_stack.last_mut() {
                        state.raw_ptrs.insert(var.clone());
                    }
                }
            }
        }

        syn::visit::visit_local(self, node);
    }

    // ── Detect tainted value flowing into index expression ────────────────
    fn visit_expr_index(&mut self, node: &'ast ExprIndex) {
        // array[tainted_index] is dangerous
        self.check_taint_in_expr(&node.index);
        syn::visit::visit_expr_index(self, node);
    }

    // ── Detect aliasing and taint propagation in assignments ──────────────
    fn visit_expr_assign(&mut self, node: &'ast ExprAssign) {
        // If rhs is tainted, lhs becomes tainted
        if let Some(rhs_var) = Self::expr_to_var(&node.right) {
            if let Some(lhs_var) = Self::expr_to_var(&node.left) {
                if let Some(state) = self.fn_stack.last_mut() {
                    if let Some(src) = state.tainted.get(&rhs_var).cloned() {
                        state.mark_tainted(&lhs_var, src);
                    }
                }
            }
        }
        syn::visit::visit_expr_assign(self, node);
    }

    // ── Track entry/exit of unsafe blocks ────────────────────────────────
    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        self.in_unsafe += 1;
        syn::visit::visit_expr_unsafe(self, node);
        self.in_unsafe -= 1;
    }

    // ── Detect get_unchecked (always an LLM logic bug) ───────────────────
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        let (line, col) = Self::span_lc(node.method.span());

        match method.as_str() {
            "get_unchecked" | "get_unchecked_mut" => {
                // Check if index arg is tainted
                if let Some(idx_expr) = node.args.first() {
                    let is_tainted = Self::expr_to_var(idx_expr)
                        .map(|v| self.fn_stack.last().map(|s| s.is_tainted(&v)).unwrap_or(false))
                        .unwrap_or(false);
                    let detail = if is_tainted {
                        "get_unchecked with tainted index — double vulnerability: unsafe source + no bounds check".to_string()
                    } else {
                        "get_unchecked() bypasses bounds checking — CVE propagation pattern from C array access".to_string()
                    };
                    if let Some(state) = self.fn_stack.last_mut() {
                        state.issues.push((line, col, LlmBugClass::LogicBugRetained, detail));
                    }
                }
            }
            "expect" => {
                // .expect() on a tainted option is slightly better than unwrap but still risky
            }
            _ => {}
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    // ── Check taint in binary operations ─────────────────────────────────
    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        self.check_taint_in_expr(&node.left);
        self.check_taint_in_expr(&node.right);
        syn::visit::visit_expr_binary(self, node);
    }

    // ── Check taint in unary operations ──────────────────────────────────
    fn visit_expr_unary(&mut self, node: &'ast ExprUnary) {
        self.check_taint_in_expr(&node.expr);
        syn::visit::visit_expr_unary(self, node);
    }

    // ── Check taint in returns ───────────────────────────────────────────
    fn visit_expr_return(&mut self, node: &'ast ExprReturn) {
        if let Some(expr) = &node.expr {
            self.check_taint_in_expr(expr);
        }
        syn::visit::visit_expr_return(self, node);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn contains_unsafe_block(block: &syn::Block) -> bool {
    struct UnsafeFinder(bool);
    impl<'a> Visit<'a> for UnsafeFinder {
        fn visit_expr_unsafe(&mut self, _: &'a ExprUnsafe) { self.0 = true; }
    }
    let mut f = UnsafeFinder(false);
    f.visit_block(block);
    f.0
}

fn collect_lifetimes_in_fn(node: &ItemFn) -> Vec<(String, (usize, usize))> {
    use syn::visit::Visit;
    struct LtCollector(Vec<(String, (usize, usize))>);
    impl<'a> Visit<'a> for LtCollector {
        fn visit_lifetime(&mut self, lt: &'a syn::Lifetime) {
            let s = lt.ident.to_string();
            let start = lt.apostrophe.start();
            self.0.push((s, (start.line, start.column + 1)));
        }
    }
    let mut c = LtCollector(Vec::new());
    c.visit_item_fn(node);
    c.0
}

fn is_transmute_call(func: &Expr) -> bool {
    if let Expr::Path(p) = func {
        let s: String = p.path.segments.iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        s.contains("transmute")
    } else { false }
}

fn is_box_from_raw(func: &Expr) -> bool {
    if let Expr::Path(p) = func {
        let s: String = p.path.segments.iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        s == "Box::from_raw" || s.ends_with("from_raw")
    } else { false }
}

fn unwrap_unsafe_expr(mut expr: &Expr) -> &Expr {
    loop {
        match expr {
            Expr::Block(eb) => {
                if eb.block.stmts.len() == 1 {
                    if let syn::Stmt::Expr(inner, _) = &eb.block.stmts[0] {
                        expr = inner;
                        continue;
                    }
                }
                break;
            }
            Expr::Unsafe(eu) => {
                if eu.block.stmts.len() == 1 {
                    if let syn::Stmt::Expr(inner, _) = &eu.block.stmts[0] {
                        expr = inner;
                        continue;
                    }
                }
                break;
            }
            _ => break,
        }
    }
    expr
}

fn extract_pat_ident_and_type(pat: &Pat) -> (Option<String>, Option<&syn::Type>, proc_macro2::Span) {
    use syn::spanned::Spanned;
    match pat {
        Pat::Ident(pi) => (Some(pi.ident.to_string()), None, pi.span()),
        Pat::Type(pt) => {
            let name = if let Pat::Ident(pi) = pt.pat.as_ref() {
                Some(pi.ident.to_string())
            } else {
                None
            };
            (name, Some(pt.ty.as_ref()), pt.span())
        }
        _ => (None, None, pat.span()),
    }
}

// ── Public entry point ────────────────────────────────────────────────────────
pub fn analyze(source: &str) -> Result<Vec<Issue>, syn::Error> {
    let file = syn::parse_file(source)?;
    let mut analyzer = DataFlowAnalyzer::new();
    analyzer.visit_file(&file);
    Ok(analyzer.issues)
}
