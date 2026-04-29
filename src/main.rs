mod analyzer;
mod rules;
mod report;
mod ast_analyzer;
mod cargo_check;
mod server;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check if running in server mode (default) or CLI mode
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() > 1 && args[1] == "--cli" {
        cli_main()
    } else {
        // Run as web server
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(server::run_server())
    }
}

fn cli_main() -> Result<(), Box<dyn std::error::Error>> {
    use clap::Parser;
    use colored::*;
    use std::path::PathBuf;
    use std::fs;

    #[derive(Parser, Debug)]
    #[command(name = "cpp2rust-debugger")]
    #[command(about = "Analyzes C/C++ to Rust transpilation issues with AST + cargo check")]
    struct Args {
        #[arg(short, long)]
        cpp: Option<PathBuf>,
        #[arg(short, long)]
        rust: PathBuf,
        #[arg(short, long, default_value = "text")]
        format: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long, default_value = "1")]
        verbose: u8,
        #[arg(long)]
        no_cargo_check: bool,
        #[arg(long)]
        no_ast: bool,
        #[arg(long)]
        no_regex: bool,
    }

    let args = Args::parse_from(std::env::args().skip(1)); // skip --cli
    println!("{}", "=== C/C++ → Rust Transpilation Debugger v0.3 ===".cyan().bold());

    let rust_path = &args.rust;
    let (rust_code, project_root) = if rust_path.is_dir() {
        let main_rs = rust_path.join("src").join("main.rs");
        let lib_rs = rust_path.join("src").join("lib.rs");
        let target = if main_rs.exists() { main_rs } else if lib_rs.exists() { lib_rs } else {
            return Err("Cargo project missing src/main.rs or src/lib.rs".into());
        };
        (fs::read_to_string(&target)?, Some(rust_path.clone()))
    } else {
        (fs::read_to_string(rust_path)?, None)
    };

    let cpp_code = match &args.cpp {
        Some(path) => Some(fs::read_to_string(path)?),
        None => None,
    };

    let mut all_issues = Vec::new();

    if !args.no_regex {
        println!("{}", "→ Running pattern + structural analysis...".dimmed());
        let mut a = analyzer::Analyzer::new(rust_code.clone(), cpp_code.clone());
        all_issues.extend(a.run());
    }
    if !args.no_ast {
        println!("{}", "→ Running AST semantic analysis (syn)...".dimmed());
        match ast_analyzer::analyze(&rust_code) {
            Ok(issues) => all_issues.extend(issues),
            Err(e) => eprintln!("AST parse failed: {}", e),
        }
    }
    if !args.no_cargo_check {
        println!("{}", "→ Running cargo check...".dimmed());
        match cargo_check::run(&rust_code, project_root.as_deref()) {
            Ok(issues) => all_issues.extend(issues),
            Err(e) => eprintln!("cargo check failed: {}", e),
        }
    }

    let rep = report::Report::new(all_issues, args.verbose);
    let output_str = match args.format.as_str() {
        "json" => rep.to_json()?,
        _ => rep.to_text(),
    };

    match args.output {
        Some(path) => fs::write(path, output_str)?,
        None => println!("{}", output_str),
    }

    Ok(())
}
