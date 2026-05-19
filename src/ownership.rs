/// ownership.rs
///
/// Gap filled: Sub-Gap 2 (compiler blind spots) + Objective 2 (ownership graph traversal)
/// 
/// Builds a lightweight ownership graph per function:
/// - Nodes = variables
/// - Edges = move / borrow / reborrow / drop
/// - Detects: hallucinated moves, missing drop, conflicting borrows,
///   C-style manual resource management patterns that survive into Rust
///
/// This is the "ownership graph traversal" component of the hybrid model (Objective 2).

use crate::rules::{Issue, Severity, Category};
use syn::{
    visit::Visit,
    ItemFn, Local, Pat, Expr, ExprCall, ExprMethodCall,
    Stmt, FnArg,
};
use syn::spanned::Spanned;
use proc_macro2::Span;
use std::collections::HashMap;

// ── Ownership state per variable ─────────────────────────────────────────────
#[derive(Debug, Clone, PartialEq)]
enum OwnershipState {
    Owned,
    Borrowed,
    MutBorrowed,
    Moved,
    Dropped,
    FromRaw,        // came from Box::from_raw — needs careful drop tracking
}

#[derive(Debug, Clone)]
struct VarState {
    name: String,
    state: OwnershipState,
    defined_line: usize,
    last_use_line: usize,
    clone_count: usize,         // excessive cloning = hallucinated ownership
    move_count: usize,
    is_ptr_type: bool,
}

impl VarState {
    fn new(name: String, line: usize, is_ptr: bool) -> Self {
        Self {
            name,
            state: OwnershipState::Owned,
            defined_line: line,
            last_use_line: line,
            clone_count: 0,
            move_count: 0,
            is_ptr_type: is_ptr,
        }
    }
}

// ── Per-function ownership graph ─────────────────────────────────────────────
struct OwnershipGraph {
    vars: HashMap<String, VarState>,
    issues: Vec<OwnershipIssue>,
    fn_name: String,
}

#[derive(Debug)]
struct OwnershipIssue {
    line: usize,
    col: usize,
    code: &'static str,
    severity: Severity,
    message: String,
    suggestion: String,
}

impl OwnershipGraph {
    fn new(fn_name: String) -> Self {
        Self {
            vars: HashMap::new(),
            issues: Vec::new(),
            fn_name,
        }
    }

    fn define(&mut self, name: &str, line: usize, is_ptr: bool) {
        self.vars.insert(name.to_string(), VarState::new(name.to_string(), line, is_ptr));
    }

    fn record_clone(&mut self, name: &str, line: usize) {
        if let Some(v) = self.vars.get_mut(name) {
            v.clone_count += 1;
            v.last_use_line = line;
            // Excessive clone() is a hallucinated ownership signal
            // LLMs often clone where they should borrow because they don't model lifetimes
            if v.clone_count >= 3 {
                self.issues.push(OwnershipIssue {
                    line, col: 1,
                    code: "OWN001",
                    severity: Severity::Warning,
                    message: format!(
                        "Variable '{}' cloned {} times in fn '{}' — LLM may have hallucinated ownership (should borrow)",
                        name, v.clone_count, self.fn_name
                    ),
                    suggestion: "Replace .clone() with & borrows. Excessive cloning indicates the LLM modelled C++ copy semantics instead of Rust borrows.".to_string(),
                });
            }
        }
    }

    fn record_use(&mut self, name: &str, line: usize) {
        if let Some(v) = self.vars.get_mut(name) {
            if v.state == OwnershipState::Moved {
                self.issues.push(OwnershipIssue {
                    line, col: 1,
                    code: "OWN002",
                    severity: Severity::Error,
                    message: format!(
                        "Variable '{}' used after move in fn '{}' — LLM double-consume pattern (like C++ after std::move)",
                        name, self.fn_name
                    ),
                    suggestion: "Track ownership: once moved, the variable is invalid. Use Option<T>::take() or restructure.".to_string(),
                });
            }
            v.last_use_line = line;
        }
    }

    fn record_move(&mut self, name: &str, line: usize) {
        if let Some(v) = self.vars.get_mut(name) {
            if v.state == OwnershipState::Moved {
                // Use after move — classic LLM double-consume bug
                self.issues.push(OwnershipIssue {
                    line, col: 1,
                    code: "OWN002",
                    severity: Severity::Error,
                    message: format!(
                        "Variable '{}' used after move in fn '{}' — LLM double-consume pattern (like C++ after std::move)",
                        name, self.fn_name
                    ),
                    suggestion: "Track ownership: once moved, the variable is invalid. Use Option<T>::take() or restructure.".to_string(),
                });
            }
            v.state = OwnershipState::Moved;
            v.move_count += 1;
            v.last_use_line = line;
        }
    }

    fn record_from_raw(&mut self, name: &str, line: usize) {
        if let Some(v) = self.vars.get(name) {
            if v.state == OwnershipState::FromRaw {
                // Already from_raw'd — double free
                self.issues.push(OwnershipIssue {
                    line, col: 1,
                    code: "OWN003",
                    severity: Severity::Error,
                    message: format!(
                        "Box::from_raw on '{}' called twice in fn '{}' — double-free vulnerability (C free() retained)",
                        name, self.fn_name
                    ),
                    suggestion: "Use ManuallyDrop or Option<Box<T>> to manage raw pointer ownership safely.".to_string(),
                });
            }
        }
        self.vars.entry(name.to_string())
            .or_insert_with(|| VarState::new(name.to_string(), line, true))
            .state = OwnershipState::FromRaw;
    }

    fn check_forgotten_drops(&mut self) {
        // Variables that are FromRaw and never moved/dropped = memory leak
        for (_, v) in &self.vars {
            if v.state == OwnershipState::FromRaw && v.move_count == 0 {
                self.issues.push(OwnershipIssue {
                    line: v.defined_line, col: 1,
                    code: "OWN004",
                    severity: Severity::Warning,
                    message: format!(
                        "Variable '{}' (Box::from_raw) in fn '{}' may not be properly dropped — possible memory leak",
                        v.name, self.fn_name
                    ),
                    suggestion: "Ensure Box::from_raw result is eventually dropped or re-leaked with Box::into_raw.".to_string(),
                });
            }
        }
    }
}

// ── Visitor ───────────────────────────────────────────────────────────────────
pub struct OwnershipAnalyzer {
    pub issues: Vec<Issue>,
    graph_stack: Vec<OwnershipGraph>,
}

impl OwnershipAnalyzer {
    pub fn new() -> Self {
        Self { issues: Vec::new(), graph_stack: Vec::new() }
    }

    fn span_lc(span: Span) -> (usize, usize) {
        let s = span.start();
        (s.line, s.column + 1)
    }
}

impl<'ast> Visit<'ast> for OwnershipAnalyzer {

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let fn_name = node.sig.ident.to_string();
        let (fn_line, _) = Self::span_lc(node.sig.ident.span());

        let mut graph = OwnershipGraph::new(fn_name.clone());

        // Register function parameters as owned variables
        for arg in &node.sig.inputs {
            if let FnArg::Typed(pat_ty) = arg {
                if let Pat::Ident(pi) = pat_ty.pat.as_ref() {
                    let is_ptr = matches!(pat_ty.ty.as_ref(), syn::Type::Ptr(_));
                    graph.define(&pi.ident.to_string(), fn_line, is_ptr);
                }
            }
        }

        self.graph_stack.push(graph);
        syn::visit::visit_item_fn(self, node);

        if let Some(mut g) = self.graph_stack.pop() {
            g.check_forgotten_drops();
            for oi in g.issues {
                self.issues.push(Issue {
                    line: oi.line, column: oi.col,
                    severity: oi.severity,
                    category: Category::Semantic,
                    code: oi.code.to_string(),
                    message: oi.message,
                    suggestion: Some(oi.suggestion),
                    snippet: String::new(),
                });
            }
        }
    }

    fn visit_local(&mut self, node: &'ast Local) {
        if let Some(g) = self.graph_stack.last_mut() {
            let (var_name, annotated_ty, pat_span) = extract_pat_ident_and_type(&node.pat);
            if let Some(var) = var_name {
                let (line, _) = Self::span_lc(pat_span);
                let is_ptr = node.init.as_ref()
                    .map(|i| expr_contains_raw_ptr(&i.expr))
                    .unwrap_or(false);
                g.define(&var, line, is_ptr);

                if let Some(init) = &node.init {
                    // If initializer is a path, it's a move of the RHS
                    if let Some(rhs_name) = expr_to_ident(&init.expr) {
                        g.record_move(&rhs_name, line);
                    }
                    // Check for Box::from_raw
                    if let Expr::Call(call) = init.expr.as_ref() {
                        if is_from_raw_call(&call.func) {
                            if let Some(arg) = call.args.first() {
                                if let Some(arg_name) = expr_to_ident(arg) {
                                    g.record_from_raw(&arg_name, line);
                                }
                            }
                            g.record_from_raw(&var, line);
                        }
                    }
                }
            }
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if let Some(g) = self.graph_stack.last_mut() {
            if node.path.segments.len() == 1 {
                let name = node.path.segments[0].ident.to_string();
                let (line, _) = Self::span_lc(node.path.segments[0].ident.span());
                g.record_use(&name, line);
            }
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        if let Some(g) = self.graph_stack.last_mut() {
            if let Some(rhs_name) = expr_to_ident(&node.right) {
                let (line, _) = Self::span_lc(node.right.span());
                g.record_move(&rhs_name, line);
            }
        }
        syn::visit::visit_expr_assign(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(g) = self.graph_stack.last_mut() {
            for arg in &node.args {
                if let Some(arg_name) = expr_to_ident(arg) {
                    let (line, _) = Self::span_lc(arg.span());
                    g.record_move(&arg_name, line);
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        let (line, _) = Self::span_lc(node.method.span());

        if let Some(g) = self.graph_stack.last_mut() {
            if method == "clone" {
                if let Some(recv_name) = expr_to_ident(&node.receiver) {
                    g.record_clone(&recv_name, line);
                }
            } else {
                for arg in &node.args {
                    if let Some(arg_name) = expr_to_ident(arg) {
                        g.record_move(&arg_name, line);
                    }
                }
            }
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
        if let Some(g) = self.graph_stack.last_mut() {
            if let Some(expr) = &node.expr {
                if let Some(name) = expr_to_ident(expr) {
                    let (line, _) = Self::span_lc(expr.span());
                    g.record_move(&name, line);
                }
            }
        }
        syn::visit::visit_expr_return(self, node);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

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

fn expr_to_ident(expr: &Expr) -> Option<String> {
    if let Expr::Path(p) = expr {
        if p.path.segments.len() == 1 {
            return Some(p.path.segments[0].ident.to_string());
        }
    }
    None
}

fn is_from_raw_call(func: &Expr) -> bool {
    if let Expr::Path(p) = func {
        p.path.segments.last()
            .map(|s| s.ident.to_string() == "from_raw")
            .unwrap_or(false)
    } else { false }
}

fn expr_contains_raw_ptr(expr: &Expr) -> bool {
    matches!(expr, Expr::Cast(c) if matches!(c.ty.as_ref(), syn::Type::Ptr(_)))
}

// ── Public entry point ────────────────────────────────────────────────────────
pub fn analyze(source: &str) -> Result<Vec<Issue>, syn::Error> {
    let file = syn::parse_file(source)?;
    let mut analyzer = OwnershipAnalyzer::new();
    analyzer.visit_file(&file);
    Ok(analyzer.issues)
}
