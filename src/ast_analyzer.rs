use crate::rules::{Issue, Severity, Category};
use syn::{visit::Visit, ItemFn, ExprUnsafe, Expr, ItemImpl, ItemStruct,
          Type, ExprMethodCall, ExprCall, ItemStatic};
use proc_macro2::Span;

pub fn analyze(source: &str) -> Result<Vec<Issue>, syn::Error> {
    let file = syn::parse_file(source)?;
    let mut visitor = AstVisitor::new();
    visitor.visit_file(&file);
    Ok(visitor.issues)
}

struct AstVisitor {
    issues: Vec<Issue>,
}

impl AstVisitor {
    fn new() -> Self {
        Self { issues: Vec::new() }
    }

    fn span_to_line_col(span: Span) -> (usize, usize) {
        let start = span.start();
        (start.line, start.column + 1)
    }

    fn add(&mut self, span: Span, severity: Severity, category: Category,
           code: &str, msg: String, suggestion: Option<String>) {
        let (line, column) = Self::span_to_line_col(span);
        self.issues.push(Issue {
            line, column, severity, category,
            code: code.to_string(),
            message: msg,
            suggestion,
            snippet: String::new(),
        });
    }
}

impl<'ast> Visit<'ast> for AstVisitor {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let name = node.sig.ident.to_string();

        if node.sig.inputs.len() > 7 {
            self.add(
                node.sig.ident.span(),
                Severity::Warning,
                Category::Idiomatic,
                "AST_FN001",
                format!("Function '{}' has {} parameters", name, node.sig.inputs.len()),
                Some("Consider grouping parameters into a struct.".to_string()),
            );
        }

        if node.sig.unsafety.is_some() {
            self.add(
                node.sig.ident.span(),
                Severity::Warning,
                Category::Memory,
                "AST_FN002",
                format!("Function '{}' is marked unsafe", name),
                Some("Verify if unsafety is truly necessary.".to_string()),
            );
        }

        syn::visit::visit_item_fn(self, node);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        let stmt_count = node.block.stmts.len();
        if stmt_count > 5 {
            self.add(
                node.unsafe_token.span,
                Severity::Warning,
                Category::Memory,
                "AST_UNS001",
                format!("Large unsafe block: {} statements", stmt_count),
                Some("Minimize unsafe scope.".to_string()),
            );
        }
        syn::visit::visit_expr_unsafe(self, node);
    }

    fn visit_item_static(&mut self, node: &'ast ItemStatic) {
        if matches!(node.mutability, syn::StaticMutability::Mut(_)) {
            self.add(
                node.ident.span(),
                Severity::Error,
                Category::Semantic,
                "AST_STATIC001",
                format!("static mut '{}' detected", node.ident),
                Some("Use OnceLock, Mutex, or atomic types.".to_string()),
            );
        }
        syn::visit::visit_item_static(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        if let syn::Fields::Named(fields) = &node.fields {
            let mut raw_ptr_fields = 0;
            for field in &fields.named {
                if matches!(field.ty, Type::Ptr(_)) {
                    raw_ptr_fields += 1;
                }
            }
            if raw_ptr_fields > 0 {
                self.add(
                    node.ident.span(),
                    Severity::Warning,
                    Category::Memory,
                    "AST_STR001",
                    format!("Struct '{}' has {} raw pointer field(s)", node.ident, raw_ptr_fields),
                    Some("Use Box<T>, Rc<T>, or references.".to_string()),
                );
            }
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if node.items.is_empty() {
            self.add(
                Span::call_site(),
                Severity::Warning,
                Category::Semantic,
                "AST_IMPL001",
                "Empty impl block detected".to_string(),
                Some("May indicate missing methods.".to_string()),
            );
        }
        syn::visit::visit_item_impl(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        match method.as_str() {
            "unwrap" => {
                self.add(
                    node.method.span(),
                    Severity::Info,
                    Category::Idiomatic,
                    "AST_MET001",
                    "unwrap() call may panic".to_string(),
                    Some("Use ? or match.".to_string()),
                );
            }
            "clone" => {
                self.add(
                    node.method.span(),
                    Severity::Hint,
                    Category::Performance,
                    "AST_MET003",
                    "clone() detected — possible C++ copy-semantics carryover".to_string(),
                    Some("Borrow with & where possible.".to_string()),
                );
            }
            _ => {}
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(p) = &*node.func {
            let path_str = p.path.segments.iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");
            if path_str.contains("transmute") {
                self.add(
                    p.path.segments.last().map(|s| s.ident.span())
                        .unwrap_or(Span::call_site()),
                    Severity::Error,
                    Category::Memory,
                    "AST_CALL001",
                    "transmute call detected — extremely dangerous".to_string(),
                    Some("Use safe alternatives.".to_string()),
                );
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}