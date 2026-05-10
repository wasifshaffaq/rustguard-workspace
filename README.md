# cpp2rust-debugger (RustGuard v0.3)

**RustGuard v0.3** is a Heuristic Semantic Analyser for C→Rust Transpilation, built upon the methodologies outlined in *Wu et al. (2025) | IEEE TrustCom*. 

It provides an extensive suite of static analysis tools to evaluate the quality, safety, and semantics of Rust code that has been transpiled from C/C++, specifically targeting the detection of unsafe paradigms, logic errors, memory safety issues, and LLM-induced hallucinations.

## 🚀 Key Features

RustGuard uses a multi-layered analysis approach to validate Rust code:

1. **Regex & CVE Retention Analysis (Layer 1)**: Identifies raw unsafe patterns and checks if known Common Vulnerabilities and Exposures (CVEs) from the original C/C++ source are inadvertently retained in the transpiled Rust code.
2. **AST Structural Analysis (Layer 2)**: Parses the Rust syntax tree (using the `syn` crate) to evaluate structural and syntax correctness.
3. **Data-Flow Taint Analysis (Layer 3)**: Detects potential data-flow issues and hallucinated logic often introduced by LLM-based transpilers.
4. **Ownership Graph Analysis (Layer 4)**: Maps and validates the Rust ownership graph to ensure safe borrowing and moving semantics.
5. **Alias & Union Analysis (Layer 5)**: Examines variable aliasing and the unsafe usage of C-style unions.
6. **Cross-Function Semantic Analysis (Layer 6)**: Evaluates semantic consistency and boundary conditions across function calls.
7. **Cargo Check Integration (Layer 7)**: Optionally runs the official `cargo check` to validate compilability and borrow-checker rules.

## 📊 Metrics

At the end of an analysis run, RustGuard generates standard quality metrics:

- **SSS (Semantic Safety Score)**: Evaluates the ratio of semantically safe functions to total functions.
- **UEI (Unsafe Exposure Index)**: Indicates the percentage of unsafe structural patterns in the codebase.
- **VRR (Vulnerability Retention Rate)**: Measures how many C/C++ vulnerabilities survived the transpilation process.

## 💻 Usage

RustGuard can operate in two distinct modes: as a localized CLI tool or as a web server.

### 1. CLI Mode

Run analysis directly on a single Rust file or an entire Cargo project directory.

```bash
# Basic analysis of a Rust file
cargo run --bin cpp2rust-debugger -- --rust path/to/file.rs

# Analysis of a Cargo project with original C source for CVE retention checking
cargo run --bin cpp2rust-debugger -- --cpp path/to/original.c --rust path/to/cargo_project

# Available options
#  -f, --format <text|json>  Output format (default: text)
#  -o, --output <path>       Write output to file
#  -v, --verbose <0|1|2>     Verbosity level
#  --no-cargo-check          Skip cargo check (faster)
```

### 2. Web Server Mode

Run RustGuard as a REST API to serve dynamic analysis requests (used for integrations and hosted environments like Railway).

```bash
# Start the web server (defaults to port 8080)
cargo run --bin cpp2rust-debugger -- --server
```

#### API Endpoint: `POST /api/analyze`

Accepts JSON payload:
```json
{
  "rust_code": "fn main() { ... }",
  "c_code": "int main() { ... }",
  "run_cargo_check": false,
  "mode": "full" // or "ast", "regex"
}
```

Returns detailed issues, metrics, and summary data.

## 🛠️ Architecture

- `src/main.rs`: Entry point handling CLI argument parsing and analysis layer orchestration.
- `src/server.rs`: Axum-based asynchronous web server for the REST API.
- `src/analyzer.rs`, `src/ast_analyzer.rs`, etc.: Core analysis modules executing the multi-layered heuristic checks.
- `src/report.rs` & `src/rules.rs`: Handles the standard issue formatting and metrics generation.

## 📝 License

*(Add appropriate license information here)*