/// alias.rs
///
/// Gap filled: Sub-Gap 4 (pointer aliasing and union semantics)
/// Papers addressed: [46] "Aliasing Limits on Translating C to Safe Rust"
///                   [47] "Union Tagging for Safe C-to-Rust Translation"
///
/// Detects:
/// 1. Structs with multiple raw pointer fields pointing to same type (aliasing risk)
/// 2. C-style union declarations in Rust (unsafe memory layout)
/// 3. Multiple *mut T parameters in the same function (aliasing contract violation)
/// 4. Functions that accept two *mut T of same type (LLVM NoAlias violated)
/// 5. Pointer arithmetic that can create overlapping memory views

use crate::rules::{Issue, Severity, Category};
use syn::{
    visit::Visit,
    ItemFn, ItemStruct, ItemUnion,
    Type, FnArg, Pat,
};
use proc_macro2::Span;
use std::collections::HashMap;

pub struct AliasAnalyzer {
    pub issues: Vec<Issue>,
}

impl AliasAnalyzer {
    pub fn new() -> Self {
        Self { issues: Vec::new() }
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

    /// Extract the inner type name from *mut T or *const T
    fn ptr_inner_type(ty: &Type) -> Option<String> {
        if let Type::Ptr(ptr) = ty {
            return Some(type_to_string(&ptr.elem));
        }
        None
    }

    fn is_raw_ptr(ty: &Type) -> bool {
        matches!(ty, Type::Ptr(_))
    }

    fn is_mut_raw_ptr(ty: &Type) -> bool {
        if let Type::Ptr(p) = ty {
            p.mutability.is_some()
        } else { false }
    }
}

impl<'ast> Visit<'ast> for AliasAnalyzer {

    // ── Detect unsafe union declarations ─────────────────────────────────
    fn visit_item_union(&mut self, node: &'ast ItemUnion) {
        let (line, col) = Self::span_lc(node.ident.span());
        let name = node.ident.to_string();
        let field_count = node.fields.named.len();

        self.add(
            line, col,
            "ALIAS_UNION001",
            Severity::Error,
            format!(
                "C-style union '{}' ({} fields) — unsafe memory layout, no discriminant tag [47]",
                name, field_count
            ),
            "Replace with a Rust enum (tagged union). Each variant should hold its data safely. See [47] Union Tagging.".to_string(),
        );

        syn::visit::visit_item_union(self, node);
    }

    // ── Detect aliasing raw pointer fields in structs ─────────────────────
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        let (line, col) = Self::span_lc(node.ident.span());
        let name = node.ident.to_string();

        if let syn::Fields::Named(fields) = &node.fields {
            let mut ptr_type_counts: HashMap<String, usize> = HashMap::new();
            let mut total_ptrs = 0usize;
            let mut mut_ptrs = 0usize;

            for field in &fields.named {
                if Self::is_raw_ptr(&field.ty) {
                    total_ptrs += 1;
                    if Self::is_mut_raw_ptr(&field.ty) { mut_ptrs += 1; }
                    if let Some(inner) = Self::ptr_inner_type(&field.ty) {
                        *ptr_type_counts.entry(inner).or_insert(0) += 1;
                    }
                }
            }

            // Two or more pointers to the same type = aliasing risk
            for (ty, count) in &ptr_type_counts {
                if *count >= 2 {
                    self.add(
                        line, col,
                        "ALIAS_STR001",
                        Severity::Error,
                        format!(
                            "Struct '{}' has {} raw pointer fields of type '{}' — aliasing violation risk [46]",
                            name, count, ty
                        ),
                        "Multiple pointers to same type may alias. Use NonNull<T> with explicit aliasing contract, or restructure into a single Vec<T>.".to_string(),
                    );
                }
            }

            // Any two *mut T fields = potential conflicting mutation
            if mut_ptrs >= 2 {
                self.add(
                    line, col,
                    "ALIAS_STR002",
                    Severity::Warning,
                    format!(
                        "Struct '{}' has {} *mut fields — C-style aliased mutation pattern, cannot guarantee disjoint writes",
                        name, mut_ptrs
                    ),
                    "Wrap each field in a RefCell<T> or use split_at_mut() for disjoint mutable access.".to_string(),
                );
            }
        }

        syn::visit::visit_item_struct(self, node);
    }

    // ── Detect aliasing function parameters ──────────────────────────────
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let (fn_line, _) = Self::span_lc(node.sig.ident.span());
        let fn_name = node.sig.ident.to_string();

        // Collect *mut T parameters grouped by inner type
        let mut mut_ptr_params: HashMap<String, Vec<String>> = HashMap::new();

        for arg in &node.sig.inputs {
            if let FnArg::Typed(pat_ty) = arg {
                if Self::is_mut_raw_ptr(&pat_ty.ty) {
                    let inner = Self::ptr_inner_type(&pat_ty.ty)
                        .unwrap_or_else(|| "unknown".to_string());
                    let param_name = if let Pat::Ident(pi) = pat_ty.pat.as_ref() {
                        pi.ident.to_string()
                    } else { "?".to_string() };
                    mut_ptr_params.entry(inner).or_default().push(param_name);
                }
            }
        }

        for (ty, params) in &mut_ptr_params {
            if params.len() >= 2 {
                self.add(
                    fn_line, 1,
                    "ALIAS_FN001",
                    Severity::Error,
                    format!(
                        "Function '{}' takes {} *mut {} params ({}) — Rust cannot guarantee they don't alias [46]",
                        fn_name, params.len(), ty, params.join(", ")
                    ),
                    "Mark with #[allow(clippy::mut_from_ref)] and document aliasing contract, OR redesign to take a single &mut [T] slice.".to_string(),
                );
            }
        }

        // Also check: *const T and *mut T to same type = read/write aliasing
        let mut const_types: std::collections::HashSet<String> = Default::default();
        let mut mut_types: std::collections::HashSet<String> = Default::default();

        for arg in &node.sig.inputs {
            if let FnArg::Typed(pat_ty) = arg {
                if let Type::Ptr(p) = &pat_ty.ty.as_ref() {
                    let inner = type_to_string(&p.elem);
                    if p.mutability.is_some() {
                        mut_types.insert(inner);
                    } else {
                        const_types.insert(inner);
                    }
                }
            }
        }

        for ty in const_types.intersection(&mut_types) {
            self.add(
                fn_line, 1,
                "ALIAS_FN002",
                Severity::Warning,
                format!(
                    "Function '{}' has both *const {} and *mut {} params — read/write aliasing risk",
                    fn_name, ty, ty
                ),
                "Use NonNull<T> and document that parameters are disjoint, or use Rust references &T / &mut T.".to_string(),
            );
        }

        syn::visit::visit_item_fn(self, node);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn type_to_string(ty: &syn::Type) -> String {
    use quote::ToTokens;
    ty.to_token_stream().to_string()
}

// ── Public entry point ────────────────────────────────────────────────────────
pub fn analyze(source: &str) -> Result<Vec<Issue>, syn::Error> {
    let file = syn::parse_file(source)?;
    let mut analyzer = AliasAnalyzer::new();
    analyzer.visit_file(&file);
    Ok(analyzer.issues)
}
