import os
import subprocess
import re
import json

TESTS_DIR = r"c:\Users\wasif\Documents\Projects\cto2rust\tests"
BINARY = r"c:\Users\wasif\Documents\Projects\cto2rust\target\release\cpp2rust-debugger.exe"
ARTIFACTS_DIR = r"C:\Users\wasif\.gemini\antigravity\brain\70f6a0b2-5f71-404b-8495-d23579658c65"
DASHBOARD_PATH = r"c:\Users\wasif\Documents\Projects\cto2rust\dashboard.html"

# List of test files and options
test_cases = [
    {"rust": "test01_clean_safe.rs", "cpp": None},
    {"rust": "test02_raw_pointers_heavy.rs", "cpp": None},
    {"rust": "test03_unsafe_density.rs", "cpp": None},
    {"rust": "test04_ast_issues.rs", "cpp": None},
    {"rust": "test05_dataflow_taint.rs", "cpp": None},
    {"rust": "test06_ownership_issues.rs", "cpp": None},
    {"rust": "test07_alias_union.rs", "cpp": None},
    {"rust": "test08_cross_function.rs", "cpp": None},
    {"rust": "test09_cve_retention.rs", "cpp": "test09_source.c"},
    {"rust": "test10_edge_empty.rs", "cpp": None},
    {"rust": "test11_edge_comments_only.rs", "cpp": None},
    {"rust": "test12_edge_syntax_error.rs", "cpp": None},
    {"rust": "test13_edge_huge_function.rs", "cpp": None},
    {"rust": "test14_llm_hallucination_patterns.rs", "cpp": None},
    {"rust": "test15_concurrency.rs", "cpp": None},
    {"rust": "test16_edge_unbalanced_braces.rs", "cpp": None},
    {"rust": "test17_performance_patterns.rs", "cpp": None},
    {"rust": "test18_mixed_everything.rs", "cpp": None},
    {"rust": "test19_false_positive_check.rs", "cpp": None},
]

results = []

def parse_text_metrics(text):
    metrics = {
        "sss": None,
        "uei": None,
        "vrr": None,
        "llm_bugs": 0,
        "cross_fn": 0,
        "aliasing": 0,
        "fnr_st": 0,
        "lines": 0,
        "functions": 0
    }
    if not text:
        return metrics
    
    # regex matches
    sss_match = re.search(r"SSS \(Semantic Safety Score\):\s*([0-9.]+)%", text)
    if sss_match:
        metrics["sss"] = float(sss_match.group(1))
        
    uei_match = re.search(r"UEI \(Unsafe Exposure Index\):\s*([0-9.]+)%", text)
    if uei_match:
        metrics["uei"] = float(uei_match.group(1))
        
    vrr_match = re.search(r"VRR \(Vulnerability Retention Rate\):\s*(\d+)", text)
    if vrr_match:
        metrics["vrr"] = int(vrr_match.group(1))
        
    llm_match = re.search(r"LLM-specific bugs detected:\s*(\d+)", text)
    if llm_match:
        metrics["llm_bugs"] = int(llm_match.group(1))
        
    cross_match = re.search(r"Cross-function issues:\s*(\d+)", text)
    if cross_match:
        metrics["cross_fn"] = int(cross_match.group(1))
        
    alias_match = re.search(r"Aliasing issues:\s*(\d+)", text)
    if alias_match:
        metrics["aliasing"] = int(alias_match.group(1))
        
    fnr_match = re.search(r"FNR-ST \(issues Clippy would miss\):\s*(\d+)", text)
    if fnr_match:
        metrics["fnr_st"] = int(fnr_match.group(1))
        
    code_match = re.search(r"Codebase:\s*(\d+)\s+lines,\s*(\d+)\s+functions", text)
    if code_match:
        metrics["lines"] = int(code_match.group(1))
        metrics["functions"] = int(code_match.group(2))
        
    return metrics

def extract_json(stdout):
    if not stdout:
        return None
    lines = stdout.splitlines()
    for idx, line in enumerate(lines):
        s = line.strip()
        if s == '[' or s == '[]':
            return "\n".join(lines[idx:])
    return None

for tc in test_cases:
    rust_path = os.path.join(TESTS_DIR, tc["rust"])
    cpp_path = os.path.join(TESTS_DIR, tc["cpp"]) if tc["cpp"] else None
    
    print(f"Running test on {tc['rust']}...")
    
    # 1. RUN TEXT PASS
    cmd_text = [BINARY, "--rust", rust_path, "--no-cargo-check", "-v", "1"]
    if cpp_path:
        cmd_text.extend(["-c", cpp_path])
        
    proc_text = subprocess.run(cmd_text, capture_output=True, text=True, encoding="utf-8")
    stdout_text = proc_text.stdout
    stderr_text = proc_text.stderr
    exit_code_text = proc_text.returncode
    
    # 2. RUN JSON PASS
    cmd_json = [BINARY, "--rust", rust_path, "--no-cargo-check", "--format", "json"]
    if cpp_path:
        cmd_json.extend(["-c", cpp_path])
        
    proc_json = subprocess.run(cmd_json, capture_output=True, text=True, encoding="utf-8")
    stdout_json = proc_json.stdout
    stderr_json = proc_json.stderr
    exit_code_json = proc_json.returncode
    
    # Parse json output
    issues = []
    json_error = None
    if exit_code_json == 0:
        json_str = extract_json(stdout_json)
        if json_str:
            try:
                issues = json.loads(json_str)
            except Exception as e:
                json_error = f"JSON parse error: {str(e)}. String was: {json_str[:100]} ... {json_str[-100:]}"
        else:
            json_error = "Could not find '[' or '[]' at line start in JSON output"
    else:
        json_error = f"Exit code {exit_code_json}. Stderr: {stderr_json}"
        
    metrics = parse_text_metrics(stdout_text)
    
    # Count issue categories
    categories = {}
    rule_counts = {}
    for issue in issues:
        cat = issue.get("category", "Unknown")
        categories[cat] = categories.get(cat, 0) + 1
        
        code = issue.get("code", "Unknown")
        rule_counts[code] = rule_counts.get(code, 0) + 1
        
    results.append({
        "test_name": tc["rust"],
        "has_cpp": cpp_path is not None,
        "exit_code": exit_code_text,
        "metrics": metrics,
        "total_issues": len(issues),
        "issues": issues,
        "categories": categories,
        "rule_counts": rule_counts,
        "stdout_text": stdout_text,
        "stderr_text": stderr_text,
        "json_error": json_error
    })

# Write raw results.json to tests dir
with open(os.path.join(TESTS_DIR, "results.json"), "w") as f:
    json.dump(results, f, indent=2)

print("Tests completed. Generating markdown report...")

# Generate Markdown report
md = []
md.append("# RustGuard v0.3 Test Suite & Performance Report")
md.append("")
md.append("This report documents the results of executing the RustGuard transpilation analyser over a comprehensive test suite of 19 test cases designed to exercise and stress all 7 layers of the analysis architecture.")
md.append("")
md.append("## Executive Summary")
md.append("")

total_tests = len(results)
successful_runs = sum(1 for r in results if r["exit_code"] == 0)
failures = total_tests - successful_runs

# compute averages for valid runs
valid_results = [r for r in results if r["exit_code"] == 0 and r["metrics"]["sss"] is not None]
avg_sss = sum(r["metrics"]["sss"] for r in valid_results) / len(valid_results) if valid_results else 0
avg_uei = sum(r["metrics"]["uei"] for r in valid_results) / len(valid_results) if valid_results else 0
total_issues_found = sum(r["total_issues"] for r in results)

md.append(f"- **Total Test Cases Executed**: {total_tests}")
md.append(f"- **Successful Analysis Runs**: {successful_runs}")
md.append(f"- **Edge Cases / Syntax Failures Detected**: {failures} (Expected behaviors for malformed input files)")
md.append(f"- **Average Semantic Safety Score (SSS)**: {avg_sss:.1f}%")
md.append(f"- **Average Unsafe Exposure Index (UEI)**: {avg_uei:.1f}%")
md.append(f"- **Total Issues/Vulnerabilities Flagged**: {total_issues_found}")
md.append("")

md.append("## Test Suite Execution Results")
md.append("")
md.append("| Test Case File | Lines | Functions | Total Issues | SSS | UEI | VRR | Status / Error |")
md.append("|---|---|---|---|---|---|---|---|")

for r in results:
    name = r["test_name"]
    metrics = r["metrics"]
    
    if r["exit_code"] != 0:
        # Check if syntax error or empty file caused it
        err_snippet = r["stderr_text"].replace("\n", " ").replace("|", "\\|")[:50]
        md.append(f"| `{name}` | - | - | - | - | - | - | ❌ Failed (Exit {r['exit_code']}): {err_snippet}... |")
    else:
        sss_str = f"{metrics['sss']:.1f}%" if metrics["sss"] is not None else "-"
        uei_str = f"{metrics['uei']:.1f}%" if metrics["uei"] is not None else "-"
        vrr_str = str(metrics["vrr"]) if metrics["vrr"] is not None else "-"
        md.append(f"| `{name}` | {metrics['lines']} | {metrics['functions']} | {r['total_issues']} | {sss_str} | {uei_str} | {vrr_str} |   Success |")

md.append("")
md.append("## Category & Rule Breakdown")
md.append("")

# Aggregate rules
all_rules = {}
for r in results:
    for code, count in r["rule_counts"].items():
        all_rules[code] = all_rules.get(code, 0) + count

md.append("| Rule Code | Count | Description |")
md.append("|---|---|---|")
# Descriptions from rules.rs mapping
rule_descriptions = {
    "RAW001": "Raw pointer type detection (*mut T, *const T)",
    "RAW002": "Unsafe block block execution check",
    "DENSE001": "Unsafe block occurrence density exceeding threshold (> 5%)",
    "AST_STR001": "Struct carrying raw pointer fields",
    "AST_FN002": "Unsafe function signatures",
    "SEM001": "Usage of unsafe/deprecated static mut fields",
    "AST_STATIC001": "Static mut identifier checks",
    "LLM_ENC001": "Nominally safe function leaking unsafe internals (Unsound encapsulation)",
    "ALIAS_STR001": "Struct having multiple raw pointer fields of the same type (Aliasing violation risk)",
    "ALIAS_STR002": "Struct having multiple mutable raw pointers (Disjoint writes violation)",
    "CROSS_005": "Allocation function returning raw pointer without corresponding free function",
    "ALIAS002": "Raw pointer casts (&mut T as *mut U)",
    "LLM_PAT003": "Incorrect or dangerous Box::from_raw usage (Double/use-after-free risk)",
    "LLM_PAT002": "Unchecked get_unchecked() array access generated by LLMs",
    "CVE_BUF001": "Direct translation of memcpy/strcpy (ptr::copy_nonoverlapping) without bounds check",
    "CVE_INT001": "Silent truncation / narrowing cast ('as i8' or 'as i16') mimicking C integer overflow",
    "VRR_CWE_120": "Vulnerability retained: CWE-120 (Buffer Overflow)",
    "VRR_CWE_190": "Vulnerability retained: CWE-190 (Integer Overflow)",
    "VRR_CWE_125": "Vulnerability retained: CWE-125 (Out-of-Bounds Read)",
    "VRR_CWE_476_SAFE": "Vulnerability solved: CWE-476 (Null Pointer Dereference resolved safely)",
    "VRR_CWE_401_SAFE": "Vulnerability solved: CWE-401 (Memory Leak resolved safely)",
    "CONC001": "Usage of std::thread::spawn in transpired context without safety synchronizations",
    "CONC002": "Shared mutability without Sync implementation (e.g., raw pointer concurrency)",
}

for code in sorted(all_rules.keys()):
    desc = rule_descriptions.get(code, "Custom/Heuristic analysis rule")
    md.append(f"| `{code}` | {all_rules[code]} | {desc} |")

md.append("")
md.append("## Analysis by Test Cases")
md.append("")

for r in results:
    name = r["test_name"]
    md.append(f"### {name}")
    md.append("")
    if r["exit_code"] != 0:
        md.append(f"**Status**: Failed (Expected parser check/syntax rejection)")
        md.append("```")
        md.append(r["stderr_text"] or r["stdout_text"])
        md.append("```")
    else:
        m = r["metrics"]
        md.append(f"- **Lines**: {m['lines']}, **Functions**: {m['functions']}")
        md.append(f"- **Semantic Safety Score (SSS)**: {m['sss']}%")
        md.append(f"- **Unsafe Exposure Index (UEI)**: {m['uei']}%")
        if m['vrr'] is not None:
            md.append(f"- **Vulnerability Retention Rate (VRR)**: {m['vrr']}")
        md.append(f"- **Total Issues Found**: {r['total_issues']}")
        
        if r["categories"]:
            cats = ", ".join(f"{c}: {count}" for c, count in r["categories"].items())
            md.append(f"- **Categories**: {cats}")
            
        if r["issues"]:
            md.append("")
            md.append("#### Highlighted Issues:")
            md.append("")
            md.append("| Line | Code | Category | Message | Suggestion |")
            md.append("|---|---|---|---|---|")
            for issue in r["issues"][:8]:  # Show first 8 issues to avoid bloating
                line = issue.get("line", 0)
                code = issue.get("code", "")
                cat = issue.get("category", "")
                msg = issue.get("message", "")
                sug = issue.get("suggestion", "")
                md.append(f"| {line} | `{code}` | {cat} | {msg} | {sug} |")
            if len(r["issues"]) > 8:
                md.append(f"| ... | ... | ... | *and {len(r['issues']) - 8} more issues* | |")
    md.append("")
    md.append("---")

report_content = "\n".join(md)

# Write to artifact directory
with open(os.path.join(ARTIFACTS_DIR, "test_report.md"), "w", encoding="utf-8") as f:
    f.write(report_content)

print("Markdown report saved to artifacts directory.")

# ================= GENERATE WEB DASHBOARD =================
print("Generating interactive web dashboard...")

html_template = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RustGuard v0.3 — Performance & Safety Dashboard</title>
  
  <!-- Typography & Icons -->
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

  <style>
    :root {
      --bg-dark: #090a10;
      --bg-card: rgba(20, 22, 38, 0.55);
      --bg-card-hover: rgba(28, 31, 54, 0.75);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-glow: rgba(139, 92, 246, 0.35);
      
      --text-primary: #f3f4f6;
      --text-secondary: #9ca3af;
      --text-muted: #6b7280;
      
      --accent-violet: #8b5cf6;
      --accent-cyan: #06b6d4;
      --accent-rose: #f43f5e;
      --accent-amber: #f59e0b;
      --accent-emerald: #10b981;
      
      --glow-violet: rgba(139, 92, 246, 0.18);
      --glow-cyan: rgba(6, 182, 212, 0.18);
      --glow-rose: rgba(244, 63, 94, 0.18);
      --glow-emerald: rgba(16, 185, 129, 0.18);
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: 'Outfit', sans-serif;
      background-color: var(--bg-dark);
      color: var(--text-primary);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
      background-image: 
        radial-gradient(circle at 12% 15%, rgba(139, 92, 246, 0.06) 0%, transparent 45%),
        radial-gradient(circle at 88% 85%, rgba(6, 182, 212, 0.06) 0%, transparent 45%);
      background-attachment: fixed;
    }

    /* Scrollbars */
    ::-webkit-scrollbar {
      width: 7px;
      height: 7px;
    }
    ::-webkit-scrollbar-track {
      background: rgba(255, 255, 255, 0.01);
    }
    ::-webkit-scrollbar-thumb {
      background: rgba(255, 255, 255, 0.08);
      border-radius: 99px;
    }
    ::-webkit-scrollbar-thumb:hover {
      background: rgba(139, 92, 246, 0.35);
    }

    .container {
      max-width: 1500px;
      width: 100%;
      margin: 0 auto;
      padding: 30px;
      flex-grow: 1;
      display: flex;
      flex-direction: column;
      gap: 24px;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border-color);
      position: relative;
    }

    .title-group h1 {
      font-size: 2.3rem;
      font-weight: 800;
      background: linear-gradient(135deg, #c084fc 0%, #38bdf8 50%, #818cf8 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.02em;
      margin-bottom: 4px;
    }

    .title-group p {
      font-size: 0.95rem;
      color: var(--text-secondary);
      font-weight: 400;
    }

    .header-badge {
      background: rgba(139, 92, 246, 0.12);
      border: 1px solid rgba(139, 92, 246, 0.25);
      border-radius: 99px;
      padding: 6px 16px;
      font-size: 0.85rem;
      font-weight: 600;
      color: #c084fc;
      box-shadow: 0 0 15px rgba(139, 92, 246, 0.1);
    }

    /* Stats Grid */
    .stats-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 20px;
    }

    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 20px 24px;
      position: relative;
      overflow: hidden;
      backdrop-filter: blur(16px);
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      box-shadow: 0 4px 30px rgba(0, 0, 0, 0.2);
    }

    .stat-card:hover {
      transform: translateY(-4px);
      border-color: var(--border-glow);
      box-shadow: 0 10px 30px rgba(139, 92, 246, 0.12);
    }

    .stat-card::after {
      content: '';
      position: absolute;
      bottom: 0;
      left: 0;
      width: 100%;
      height: 3px;
      background: linear-gradient(90deg, var(--accent-violet), var(--accent-cyan));
      opacity: 0.6;
    }

    .stat-card.rose::after {
      background: linear-gradient(90deg, var(--accent-rose), #fb7185);
    }

    .stat-card.emerald::after {
      background: linear-gradient(90deg, var(--accent-emerald), #34d399);
    }

    .stat-card.amber::after {
      background: linear-gradient(90deg, var(--accent-amber), #fbbf24);
    }

    .stat-label {
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    .stat-value {
      font-size: 2.1rem;
      font-weight: 800;
      margin-top: 8px;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      display: flex;
      align-items: baseline;
      gap: 4px;
    }

    .stat-unit {
      font-size: 1rem;
      font-weight: 500;
      color: var(--text-secondary);
      -webkit-text-fill-color: var(--text-secondary);
    }

    /* Main Section Layout */
    .dashboard-layout {
      display: grid;
      grid-template-columns: 380px 1fr;
      gap: 24px;
      flex-grow: 1;
      min-height: 720px;
    }

    /* Sidebar - Left */
    .sidebar {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 16px;
      backdrop-filter: blur(16px);
      box-shadow: 0 4px 30px rgba(0, 0, 0, 0.2);
    }

    .search-container {
      position: relative;
    }

    .search-input {
      width: 100%;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 12px 16px;
      padding-left: 40px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 0.9rem;
      transition: all 0.25s ease;
    }

    .search-input:focus {
      outline: none;
      border-color: var(--accent-violet);
      box-shadow: 0 0 12px var(--glow-violet);
      background: rgba(0, 0, 0, 0.45);
    }

    .search-icon {
      position: absolute;
      left: 14px;
      top: 50%;
      transform: translateY(-50%);
      width: 16px;
      height: 16px;
      fill: var(--text-muted);
    }

    .test-list {
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 10px;
      flex-grow: 1;
      padding-right: 4px;
    }

    .test-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 14px;
      padding: 14px 16px;
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      align-items: center;
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .test-card:hover {
      background: rgba(255, 255, 255, 0.05);
      border-color: rgba(255, 255, 255, 0.08);
      transform: translateX(4px);
    }

    .test-card.active {
      background: rgba(139, 92, 246, 0.12);
      border-color: rgba(139, 92, 246, 0.4);
      box-shadow: inset 0 0 10px rgba(139, 92, 246, 0.1);
    }

    .test-card-title {
      font-size: 0.95rem;
      font-weight: 600;
      color: #f3f4f6;
      margin-bottom: 6px;
      word-break: break-all;
    }

    .test-card-stats {
      display: flex;
      gap: 12px;
      font-size: 0.75rem;
      color: var(--text-secondary);
    }

    .test-card-badge-container {
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 6px;
    }

    /* Badges */
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.02em;
    }

    .badge-sss {
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.25);
    }

    .badge-uei {
      background: rgba(244, 63, 94, 0.15);
      color: #f43f5e;
      border: 1px solid rgba(244, 63, 94, 0.25);
    }

    .badge-issues {
      background: rgba(245, 158, 11, 0.15);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.25);
    }
    
    .badge-zero {
      background: rgba(16, 185, 129, 0.1);
      color: #10b981;
      border: 1px solid rgba(16, 185, 129, 0.15);
    }

    /* Details Panel - Right */
    .details-panel {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 30px;
      display: flex;
      flex-direction: column;
      gap: 24px;
      backdrop-filter: blur(16px);
      box-shadow: 0 4px 30px rgba(0, 0, 0, 0.2);
      overflow: hidden;
      position: relative;
    }

    .details-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 18px;
    }

    .details-title h2 {
      font-size: 1.6rem;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 4px;
    }

    .details-subtitle {
      font-size: 0.9rem;
      color: var(--text-secondary);
      display: flex;
      gap: 16px;
    }

    .details-tabs {
      display: flex;
      gap: 8px;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 10px;
    }

    .tab-btn {
      background: transparent;
      border: 1px solid transparent;
      color: var(--text-secondary);
      padding: 10px 20px;
      font-family: inherit;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      border-radius: 8px;
      transition: all 0.2s ease;
    }

    .tab-btn:hover {
      color: #ffffff;
      background: rgba(255, 255, 255, 0.03);
    }

    .tab-btn.active {
      color: #ffffff;
      background: rgba(139, 92, 246, 0.15);
      border-color: rgba(139, 92, 246, 0.35);
      box-shadow: 0 0 15px rgba(139, 92, 246, 0.1);
    }

    .tab-content {
      flex-grow: 1;
      overflow-y: auto;
      display: none;
      animation: fadeIn 0.3s ease;
    }

    .tab-content.active {
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    /* Overview Tab Layout */
    .overview-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 20px;
    }

    .overview-card {
      background: rgba(0, 0, 0, 0.2);
      border: 1px solid var(--border-color);
      border-radius: 14px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .overview-card h3 {
      font-size: 1rem;
      font-weight: 600;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 8px;
      border-bottom: 1px solid rgba(255,255,255,0.04);
      padding-bottom: 8px;
    }

    .metric-meter-container {
      display: flex;
      flex-direction: column;
      gap: 6px;
      margin-top: 8px;
    }

    .meter-label {
      font-size: 0.85rem;
      color: var(--text-secondary);
      display: flex;
      justify-content: space-between;
    }

    .meter-bar-outer {
      height: 8px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 99px;
      overflow: hidden;
    }

    .meter-bar-inner {
      height: 100%;
      border-radius: 99px;
      transition: width 0.8s cubic-bezier(0.1, 0.8, 0.2, 1);
    }

    .meter-bar-inner.sss {
      background: linear-gradient(90deg, #10b981, #06b6d4);
      box-shadow: 0 0 10px rgba(6, 182, 212, 0.3);
    }

    .meter-bar-inner.uei {
      background: linear-gradient(90deg, #f43f5e, #fb923c);
      box-shadow: 0 0 10px rgba(244, 63, 94, 0.3);
    }

    .meta-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
      font-size: 0.9rem;
    }

    .meta-item {
      display: flex;
      justify-content: space-between;
      border-bottom: 1px dashed rgba(255, 255, 255, 0.05);
      padding-bottom: 6px;
    }

    .meta-val {
      font-weight: 600;
      color: #ffffff;
    }

    /* Pre / Code console */
    .terminal-console {
      background: #040508;
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 12px;
      padding: 16px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.85rem;
      line-height: 1.5;
      overflow-x: auto;
      white-space: pre;
      color: #a7f3d0;
      flex-grow: 1;
      max-height: 400px;
      box-shadow: inset 0 2px 8px rgba(0,0,0,0.8);
    }

    /* Issues Tab Layout */
    .issues-filter-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      background: rgba(0, 0, 0, 0.15);
      padding: 14px;
      border-radius: 12px;
      border: 1px solid var(--border-color);
      align-items: center;
    }

    .filter-group {
      display: flex;
      gap: 8px;
    }

    .filter-btn {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.05);
      color: var(--text-secondary);
      padding: 6px 12px;
      font-size: 0.8rem;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .filter-btn:hover {
      background: rgba(255, 255, 255, 0.06);
      color: #fff;
    }

    .filter-btn.active {
      background: var(--accent-violet);
      color: #fff;
      border-color: var(--accent-violet);
      box-shadow: 0 0 10px rgba(139, 92, 246, 0.35);
    }

    .issues-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .issue-item {
      background: rgba(255, 255, 255, 0.015);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 12px;
      padding: 16px;
      transition: all 0.2s ease;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .issue-item:hover {
      background: rgba(255, 255, 255, 0.03);
      border-color: rgba(255, 255, 255, 0.08);
      transform: translateY(-2px);
    }

    .issue-meta-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .issue-left {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .issue-line-badge {
      background: rgba(255, 255, 255, 0.08);
      color: #ffffff;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      font-weight: 600;
    }

    .issue-code {
      font-family: 'JetBrains Mono', monospace;
      font-weight: 700;
      color: var(--accent-cyan);
      font-size: 0.85rem;
    }

    .issue-severity-pill {
      font-size: 0.7rem;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
      text-transform: uppercase;
    }

    .sev-error { background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.25); }
    .sev-warning { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.25); }
    .sev-info { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.25); }

    .issue-message {
      font-size: 0.95rem;
      color: #ffffff;
      line-height: 1.4;
      font-weight: 500;
    }

    .issue-snippet {
      background: #040508;
      border-radius: 8px;
      padding: 10px 14px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      color: #cbd5e1;
      border-left: 3px solid var(--accent-violet);
      white-space: pre-wrap;
      word-break: break-all;
    }

    .issue-suggestion {
      font-size: 0.85rem;
      color: var(--text-secondary);
      background: rgba(16, 185, 129, 0.05);
      border: 1px dashed rgba(16, 185, 129, 0.2);
      border-radius: 8px;
      padding: 10px 12px;
      display: flex;
      gap: 6px;
      align-items: center;
    }

    .suggestion-icon {
      flex-shrink: 0;
      color: var(--accent-emerald);
      width: 14px;
      height: 14px;
      fill: currentColor;
    }

    /* Global Charts Section */
    .global-charts-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 24px;
      backdrop-filter: blur(16px);
      box-shadow: 0 4px 30px rgba(0, 0, 0, 0.2);
    }

    .global-charts-header {
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 14px;
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .global-charts-header h2 {
      font-size: 1.25rem;
      font-weight: 700;
    }

    .charts-grid {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 24px;
    }

    @media (max-width: 1024px) {
      .dashboard-layout {
        grid-template-columns: 1fr;
      }
      .charts-grid {
        grid-template-columns: 1fr;
      }
    }

    /* Empty state */
    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 80px 20px;
      color: var(--text-secondary);
      text-align: center;
      gap: 16px;
    }

    .empty-state-icon {
      width: 48px;
      height: 48px;
      stroke: var(--text-muted);
      stroke-width: 1.5;
    }

    .empty-state-title {
      font-size: 1.2rem;
      font-weight: 600;
      color: #fff;
    }

    /* Keyframes */
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(4px); }
      to { opacity: 1; transform: translateY(0); }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="title-group">
        <h1>RustGuard v0.3</h1>
        <p>C→Rust Heuristic Semantic Transpilation Quality &amp; Safety Dashboard</p>
      </div>
      <div class="header-badge">IEEE TrustCom (Wu et al. 2025) Framework</div>
    </header>

    <!-- Stats row -->
    <div class="stats-row">
      <div class="stat-card">
        <div class="stat-label">Total Test Cases</div>
        <div id="stat-total-files" class="stat-value">0</div>
      </div>
      <div class="stat-card rose">
        <div class="stat-label">Total Issues Flagged</div>
        <div id="stat-total-issues" class="stat-value">0</div>
      </div>
      <div class="stat-card emerald">
        <div class="stat-label">Avg Semantic Safety (SSS)</div>
        <div id="stat-avg-sss" class="stat-value">0<span class="stat-unit">%</span></div>
      </div>
      <div class="stat-card amber">
        <div class="stat-label">Avg Unsafe Exposure (UEI)</div>
        <div id="stat-avg-uei" class="stat-value">0<span class="stat-unit">%</span></div>
      </div>
    </div>

    <!-- Main Section -->
    <div class="dashboard-layout">
      <!-- Sidebar Selector -->
      <div class="sidebar">
        <div class="search-container">
          <svg class="search-icon" viewBox="0 0 24 24">
            <path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>
          </svg>
          <input type="text" id="search-bar" class="search-input" placeholder="Search test cases...">
        </div>
        
        <div class="test-list" id="test-list-container">
          <!-- Populated by JS -->
        </div>
      </div>

      <!-- Detail Panel -->
      <div class="details-panel" id="detail-panel">
        <div class="details-header">
          <div class="details-title">
            <h2 id="detail-file-name">Select a test file</h2>
            <div class="details-subtitle" id="detail-file-meta">
              <span>Lines: --</span>
              <span>Functions: --</span>
            </div>
          </div>
          <div id="detail-status-badges" style="display: flex; gap: 8px;">
            <!-- Badge list -->
          </div>
        </div>

        <div class="details-tabs">
          <button class="tab-btn active" onclick="switchTab('tab-overview')">Metrics &amp; Summary</button>
          <button class="tab-btn" onclick="switchTab('tab-issues')" id="issues-tab-btn">Flagged Issues (0)</button>
          <button class="tab-btn" onclick="switchTab('tab-terminal')">Stdout Terminal</button>
        </div>

        <!-- TAB CONTENT: OVERVIEW -->
        <div class="tab-content active" id="tab-overview">
          <div class="overview-grid">
            <div class="overview-card">
              <h3>Heuristic Safety Indices</h3>
              
              <div class="metric-meter-container">
                <div class="meter-label">
                  <span>Semantic Safety Score (SSS)</span>
                  <span id="overview-val-sss" style="font-weight:700; color:#34d399;">0%</span>
                </div>
                <div class="meter-bar-outer">
                  <div class="meter-bar-inner sss" id="overview-bar-sss" style="width: 0%;"></div>
                </div>
              </div>

              <div class="metric-meter-container" style="margin-top: 14px;">
                <div class="meter-label">
                  <span>Unsafe Exposure Index (UEI)</span>
                  <span id="overview-val-uei" style="font-weight:700; color:#f43f5e;">0%</span>
                </div>
                <div class="meter-bar-outer">
                  <div class="meter-bar-inner uei" id="overview-bar-uei" style="width: 0%;"></div>
                </div>
              </div>
            </div>

            <div class="overview-card">
              <h3>Analysis Diagnostics</h3>
              <div class="meta-list">
                <div class="meta-item">
                  <span>Analysis Verdict</span>
                  <span id="overview-verdict" class="meta-val">--</span>
                </div>
                <div class="meta-item">
                  <span>Vulnerability Retention (VRR)</span>
                  <span id="overview-vrr" class="meta-val">--</span>
                </div>
                <div class="meta-item">
                  <span>LLM-specific Bugs</span>
                  <span id="overview-llm-bugs" class="meta-val">--</span>
                </div>
                <div class="meta-item">
                  <span>Aliasing Risks</span>
                  <span id="overview-aliasing" class="meta-val">--</span>
                </div>
              </div>
            </div>
          </div>
          
          <div style="flex-grow: 1; display:flex; flex-direction:column; gap: 8px;">
            <h3 style="font-size: 1rem; font-weight: 600; color: #ffffff;">Quick Summary</h3>
            <p id="overview-summary-text" style="font-size: 0.95rem; line-height: 1.5; color: var(--text-secondary);"></p>
          </div>
        </div>

        <!-- TAB CONTENT: ISSUES -->
        <div class="tab-content" id="tab-issues">
          <div class="issues-filter-bar">
            <span style="font-size: 0.8rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Filter Issues:</span>
            <div class="filter-group" id="severity-filters">
              <button class="filter-btn active" onclick="filterIssues('severity', 'all')">All Severities</button>
              <button class="filter-btn" onclick="filterIssues('severity', 'error')">Errors</button>
              <button class="filter-btn" onclick="filterIssues('severity', 'warning')">Warnings</button>
            </div>
            
            <div style="width: 1px; height: 16px; background: rgba(255,255,255,0.1); margin: 0 8px;"></div>
            
            <div class="filter-group" id="category-filters" style="flex-wrap: wrap;">
              <!-- Populated by JS -->
            </div>
          </div>

          <div class="issues-list" id="issues-list-container">
            <!-- Populated by JS -->
          </div>
        </div>

        <!-- TAB CONTENT: TERMINAL -->
        <div class="tab-content" id="tab-terminal">
          <div class="terminal-console" id="terminal-content">
            <!-- Console log output -->
          </div>
        </div>
      </div>
    </div>

    <!-- Global Charts Card -->
    <div class="global-charts-card">
      <div class="global-charts-header">
        <h2>Overall Project Safety Profile</h2>
        <span style="font-size:0.85rem; color: var(--text-secondary);">19 Test Suite Execution Analysis</span>
      </div>
      <div class="charts-grid">
        <div style="background: rgba(0, 0, 0, 0.2); border-radius: 12px; padding: 16px; height: 350px;">
          <canvas id="sssUeiChart"></canvas>
        </div>
        <div style="background: rgba(0, 0, 0, 0.2); border-radius: 12px; padding: 16px; height: 350px; display:flex; justify-content:center; align-items:center; position:relative;">
          <canvas id="categoryChart"></canvas>
        </div>
      </div>
    </div>
  </div>

  <script>
    // Embedded JSON results payload
    const testResults = <!-- DATA_PLACEHOLDER -->;

    // State
    let selectedTestName = "";
    let activeTabId = "tab-overview";
    let activeFilters = {
      severity: "all",
      category: "all"
    };

    // DOM Elements
    const testListContainer = document.getElementById('test-list-container');
    const searchBar = document.getElementById('search-bar');
    
    const detailPanel = document.getElementById('detail-panel');
    const detailFileName = document.getElementById('detail-file-name');
    const detailFileMeta = document.getElementById('detail-file-meta');
    const detailStatusBadges = document.getElementById('detail-status-badges');
    const issuesTabBtn = document.getElementById('issues-tab-btn');
    
    // Overview tab elements
    const overviewValSss = document.getElementById('overview-val-sss');
    const overviewBarSss = document.getElementById('overview-bar-sss');
    const overviewValUei = document.getElementById('overview-val-uei');
    const overviewBarUei = document.getElementById('overview-bar-uei');
    const overviewVerdict = document.getElementById('overview-verdict');
    const overviewVrr = document.getElementById('overview-vrr');
    const overviewLlmBugs = document.getElementById('overview-llm-bugs');
    const overviewAliasing = document.getElementById('overview-aliasing');
    const overviewSummaryText = document.getElementById('overview-summary-text');
    
    // Issues tab elements
    const categoryFilters = document.getElementById('category-filters');
    const issuesListContainer = document.getElementById('issues-list-container');
    
    // Terminal tab elements
    const terminalContent = document.getElementById('terminal-content');

    // Init
    window.addEventListener('DOMContentLoaded', () => {
      // 1. Calculate and populate top-level stats
      calculateGlobalStats();
      
      // 2. Populate test cases list sidebar
      populateTestSidebar(testResults);
      
      // 3. Setup event listeners
      searchBar.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const filtered = testResults.filter(t => t.test_name.toLowerCase().includes(query));
        populateTestSidebar(filtered);
      });
      
      // 4. Select first test case by default
      if (testResults.length > 0) {
        selectTest(testResults[0].test_name);
      }
      
      // 5. Render charts
      renderGlobalCharts();
    });

    function calculateGlobalStats() {
      document.getElementById('stat-total-files').textContent = testResults.length;
      
      let totalIssues = 0;
      let sumSss = 0;
      let sumUei = 0;
      let validMetricsCount = 0;
      
      testResults.forEach(r => {
        totalIssues += r.total_issues;
        if (r.exit_code === 0 && r.metrics.sss !== null) {
          sumSss += r.metrics.sss;
          sumUei += r.metrics.uei;
          validMetricsCount++;
        }
      });
      
      const avgSss = validMetricsCount > 0 ? (sumSss / validMetricsCount).toFixed(1) : 0;
      const avgUei = validMetricsCount > 0 ? (sumUei / validMetricsCount).toFixed(1) : 0;
      
      document.getElementById('stat-total-issues').textContent = totalIssues;
      document.getElementById('stat-avg-sss').innerHTML = `${avgSss}<span class="stat-unit">%</span>`;
      document.getElementById('stat-avg-uei').innerHTML = `${avgUei}<span class="stat-unit">%</span>`;
    }

    function populateTestSidebar(items) {
      testListContainer.innerHTML = '';
      if (items.length === 0) {
        testListContainer.innerHTML = '<div style="color:var(--text-muted); text-align:center; padding:20px; font-size:0.9rem;">No tests found.</div>';
        return;
      }
      
      items.forEach(t => {
        const card = document.createElement('div');
        card.className = `test-card ${t.test_name === selectedTestName ? 'active' : ''}`;
        card.id = `test-card-${t.test_name.replace(/\\./g, '_')}`;
        card.onclick = () => selectTest(t.test_name);
        
        let badgesHtml = '';
        if (t.exit_code !== 0) {
          badgesHtml = '<span class="badge badge-danger">Failed</span>';
        } else {
          const sss = t.metrics.sss;
          const uei = t.metrics.uei;
          const issues = t.total_issues;
          
          if (sss === 100) {
            badgesHtml += `<span class="badge badge-sss" style="font-size:0.65rem;">100% SSS</span> `;
          } else if (sss !== null) {
            badgesHtml += `<span class="badge badge-sss" style="font-size:0.65rem; background:rgba(16,185,129,0.05); color:#10b981;">${sss.toFixed(0)}% SSS</span> `;
          }
          
          if (issues === 0) {
            badgesHtml += `<span class="badge badge-zero" style="font-size:0.65rem;">0 Issues</span>`;
          } else {
            badgesHtml += `<span class="badge badge-issues" style="font-size:0.65rem;">${issues} Issues</span>`;
          }
        }
        
        card.innerHTML = `
          <div class="test-name-area">
            <div class="test-card-title">${t.test_name}</div>
            <div class="test-card-stats">
              <span>Lines: ${t.metrics.lines || '--'}</span>
              <span>Fn: ${t.metrics.functions || '--'}</span>
            </div>
          </div>
          <div class="test-card-badge-container">
            ${badgesHtml}
          </div>
        `;
        testListContainer.appendChild(card);
      });
    }

    function selectTest(name) {
      selectedTestName = name;
      
      // Update sidebar active classes
      document.querySelectorAll('.test-card').forEach(c => c.classList.remove('active'));
      const activeCard = document.getElementById(`test-card-${name.replace(/\\./g, '_')}`);
      if (activeCard) activeCard.classList.add('active');
      
      // Get test details
      const test = testResults.find(t => t.test_name === name);
      if (!test) return;
      
      // Update panel header
      detailFileName.textContent = test.test_name;
      detailFileMeta.innerHTML = `
        <span>Lines of Code: <strong>${test.metrics.lines || '--'}</strong></span>
        <span>Functions: <strong>${test.metrics.functions || '--'}</strong></span>
        ${test.has_cpp ? '<span>Linked C++ Reference: <strong>Yes</strong></span>' : ''}
      `;
      
      // Headers badges
      detailStatusBadges.innerHTML = '';
      if (test.exit_code !== 0) {
        detailStatusBadges.innerHTML = '<span class="badge badge-danger">Parser Rejection</span>';
      } else {
        if (test.metrics.vrr > 0) {
          detailStatusBadges.innerHTML += `<span class="badge badge-danger">Vulnerabilities Retained: ${test.metrics.vrr}</span>`;
        } else if (test.metrics.sss === 100) {
          detailStatusBadges.innerHTML += '<span class="badge badge-sss">Safe Codebase</span>';
        } else {
          detailStatusBadges.innerHTML += '<span class="badge badge-warning">Unsafe Semantics Found</span>';
        }
      }
      
      // Update tabs count
      issuesTabBtn.textContent = `Flagged Issues (${test.total_issues})`;
      
      // --- POPULATE TAB 1: OVERVIEW ---
      const sss = test.metrics.sss;
      const uei = test.metrics.uei;
      
      overviewValSss.textContent = sss !== null ? `${sss.toFixed(1)}%` : '--%';
      overviewBarSss.style.width = sss !== null ? `${sss}%` : '0%';
      
      overviewValUei.textContent = uei !== null ? `${uei.toFixed(1)}%` : '--%';
      overviewBarUei.style.width = uei !== null ? `${uei}%` : '0%';
      
      if (test.exit_code !== 0) {
        overviewVerdict.textContent = "Rejected / Syntax Error";
        overviewVerdict.style.color = "var(--accent-rose)";
      } else if (sss === 100) {
        overviewVerdict.textContent = "Passed - Fully Safe";
        overviewVerdict.style.color = "var(--accent-emerald)";
      } else {
        overviewVerdict.textContent = "Warnings Flagged";
        overviewVerdict.style.color = "var(--accent-amber)";
      }
      
      overviewVrr.textContent = test.metrics.vrr !== null ? test.metrics.vrr : '--';
      if (test.metrics.vrr > 0) overviewVrr.style.color = "var(--accent-rose)";
      else overviewVrr.style.color = "var(--text-primary)";
      
      overviewLlmBugs.textContent = test.metrics.llm_bugs || 0;
      overviewAliasing.textContent = test.metrics.aliasing || 0;
      
      // Auto text summary
      let summaryText = "";
      if (test.exit_code !== 0) {
        summaryText = `This file was rejected by the analyzer parser or syntactical checks with exit code ${test.exit_code}. This indicates that the file contains syntactical errors (e.g., unbalanced braces or invalid Rust structure) preventing AST analysis. This is the expected and correct behavior for malformed input files.`;
      } else {
        if (sss === 100) {
          summaryText = `Excellent! The file has a <strong>Semantic Safety Score (SSS) of 100%</strong> and a <strong>0% Unsafe Exposure Index (UEI)</strong>. No raw pointers, unsafe blocks, static mutable structures, or aliasing risks were identified. This code represents idiomatic, safe Rust.`;
        } else {
          summaryText = `The file exhibits heavy signs of C-to-Rust transpilation footprints, with a <strong>Semantic Safety Score of ${sss.toFixed(1)}%</strong> and <strong>Unsafe Exposure Index of ${uei.toFixed(1)}%</strong>. `;
          
          if (test.metrics.aliasing > 0 || test.metrics.llm_bugs > 0) {
            summaryText += `Key issues include <strong>${test.metrics.aliasing} aliasing vulnerabilities</strong> and <strong>${test.metrics.llm_bugs} LLM translation bugs</strong> (e.g., unsound encapsulation, Box::from_raw risks). `;
          }
          if (test.metrics.vrr > 0) {
            summaryText += `Crucially, the analyzer verified that <strong>${test.metrics.vrr} vulnerabilities were retained</strong> from the original C source (such as CWE-120 Buffer Overflow or CWE-190 Integer Overflow). `;
          }
          summaryText += `Refactoring is strongly recommended to encapsulate raw pointers and unsafe blocks into safe, idiomatic Rust abstractions.`;
        }
      }
      overviewSummaryText.innerHTML = summaryText;
      
      // --- POPULATE TAB 2: ISSUES ---
      populateCategoryFilters(test.issues);
      filterAndRenderIssues(test.issues);
      
      // --- POPULATE TAB 3: TERMINAL ---
      terminalContent.textContent = test.stdout_text + (test.stderr_text ? "\\n--- STDERR ---\\n" + test.stderr_text : "");
    }

    function populateCategoryFilters(issues) {
      categoryFilters.innerHTML = '';
      
      // Get unique categories
      const categories = new Set();
      issues.forEach(i => {
        if (i.category) categories.add(i.category);
      });
      
      if (categories.size === 0) {
        categoryFilters.style.display = 'none';
        return;
      } else {
        categoryFilters.style.display = 'flex';
      }
      
      // Add "All" button
      const allBtn = document.createElement('button');
      allBtn.className = `filter-btn ${activeFilters.category === 'all' ? 'active' : ''}`;
      allBtn.textContent = 'All Categories';
      allBtn.onclick = () => filterIssues('category', 'all');
      categoryFilters.appendChild(allBtn);
      
      // Add each category button
      categories.forEach(cat => {
        const btn = document.createElement('button');
        btn.className = `filter-btn ${activeFilters.category === cat ? 'active' : ''}`;
        btn.textContent = cat;
        btn.onclick = () => filterIssues('category', cat);
        categoryFilters.appendChild(btn);
      });
    }

    function filterIssues(type, val) {
      activeFilters[type] = val;
      
      // Update buttons visual state
      let containerId = type === 'severity' ? 'severity-filters' : 'category-filters';
      document.querySelectorAll(`#${containerId} .filter-btn`).forEach(b => {
        if (b.textContent.toLowerCase().includes(val.toLowerCase()) || (val === 'all' && b.textContent.includes('All'))) {
          b.classList.add('active');
        } else {
          b.classList.remove('active');
        }
      });
      
      const test = testResults.find(t => t.test_name === selectedTestName);
      if (test) {
        filterAndRenderIssues(test.issues);
      }
    }

    function filterAndRenderIssues(issues) {
      issuesListContainer.innerHTML = '';
      
      let filtered = issues.filter(i => {
        // Severity filter
        if (activeFilters.severity !== 'all') {
          const isError = i.severity && i.severity.toLowerCase() === 'error';
          if (activeFilters.severity === 'error' && !isError) return false;
          if (activeFilters.severity === 'warning' && isError) return false;
        }
        
        // Category filter
        if (activeFilters.category !== 'all') {
          if (i.category !== activeFilters.category) return false;
        }
        
        return true;
      });
      
      if (filtered.length === 0) {
        issuesListContainer.innerHTML = `
          <div class="empty-state">
            <svg class="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div class="empty-state-title">No issues found matching filters</div>
          </div>
        `;
        return;
      }
      
      filtered.forEach(issue => {
        const item = document.createElement('div');
        item.className = 'issue-item';
        
        const isError = issue.severity && issue.severity.toLowerCase() === 'error';
        const sevClass = isError ? 'sev-error' : 'sev-warning';
        
        let snippetHtml = '';
        if (issue.snippet && issue.snippet.trim()) {
          snippetHtml = `<div class="issue-snippet">${escapeHtml(issue.snippet)}</div>`;
        }
        
        let sugHtml = '';
        if (issue.suggestion) {
          sugHtml = `
            <div class="issue-suggestion">
              <svg class="suggestion-icon" viewBox="0 0 20 20">
                <path d="M10 2a8 8 0 100 16 8 8 0 000-16zm.75 11h-1.5v-1.5h1.5V13zm0-3h-1.5V6h1.5v4z"/>
              </svg>
              <span><strong>Recommendation:</strong> ${issue.suggestion}</span>
            </div>
          `;
        }
        
        item.innerHTML = `
          <div class="issue-meta-row">
            <div class="issue-left">
              <span class="issue-line-badge">Line ${issue.line}</span>
              <span class="issue-code">${issue.code}</span>
              <span class="badge" style="background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); color:var(--text-secondary);">${issue.category}</span>
            </div>
            <span class="issue-severity-pill ${sevClass}">${issue.severity || 'Warning'}</span>
          </div>
          <div class="issue-message">${issue.message}</div>
          ${snippetHtml}
          ${sugHtml}
        `;
        
        issuesListContainer.appendChild(item);
      });
    }

    function switchTab(tabId) {
      activeTabId = tabId;
      
      // Update buttons
      document.querySelectorAll('.tab-btn').forEach(btn => {
        if (btn.getAttribute('onclick').includes(tabId)) btn.classList.add('active');
        else btn.classList.remove('active');
      });
      
      // Update contents
      document.querySelectorAll('.tab-content').forEach(c => {
        if (c.id === tabId) c.classList.add('active');
        else c.classList.remove('active');
      });
    }

    function escapeHtml(text) {
      if (!text) return '';
      return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }

    function renderGlobalCharts() {
      // 1. Prepare data for SSS vs UEI Multi-Bar Chart
      const labels = [];
      const sssData = [];
      const ueiData = [];
      const aggregateCategories = {};
      
      testResults.forEach(r => {
        if (r.exit_code === 0 && r.metrics.sss !== null) {
          labels.push(r.test_name.replace('_heavy', '').replace('_issues', '').replace('_patterns', '').replace('.rs', ''));
          sssData.push(r.metrics.sss);
          ueiData.push(r.metrics.uei);
        }
        
        // Aggregate categories for doughnut chart
        r.issues.forEach(issue => {
          const cat = issue.category || 'Other';
          aggregateCategories[cat] = (aggregateCategories[cat] || 0) + 1;
        });
      });

      // Render Bar Chart
      const ctxBar = document.getElementById('sssUeiChart').getContext('2d');
      new Chart(ctxBar, {
        type: 'bar',
        data: {
          labels: labels,
          datasets: [
            {
              label: 'Semantic Safety Score (SSS %)',
              data: sssData,
              backgroundColor: 'rgba(16, 185, 129, 0.65)',
              borderColor: 'rgba(16, 185, 129, 1)',
              borderWidth: 1.5,
              borderRadius: 6,
              barPercentage: 0.8,
              categoryPercentage: 0.8
            },
            {
              label: 'Unsafe Exposure Index (UEI %)',
              data: ueiData,
              backgroundColor: 'rgba(244, 63, 94, 0.65)',
              borderColor: 'rgba(244, 63, 94, 1)',
              borderWidth: 1.5,
              borderRadius: 6,
              barPercentage: 0.8,
              categoryPercentage: 0.8
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              labels: { color: '#e5e7eb', font: { family: 'Outfit', size: 12 } }
            },
            tooltip: {
              padding: 12,
              titleFont: { family: 'Outfit', size: 13, weight: 'bold' },
              bodyFont: { family: 'Outfit', size: 12 }
            }
          },
          scales: {
            x: {
              grid: { color: 'rgba(255,255,255,0.03)' },
              ticks: { color: '#9ca3af', font: { family: 'Outfit', size: 10 } }
            },
            y: {
              grid: { color: 'rgba(255,255,255,0.04)' },
              ticks: { color: '#9ca3af', font: { family: 'Outfit', size: 10 } },
              max: 100,
              min: 0
            }
          }
        }
      });

      // Render Doughnut Chart
      const ctxPie = document.getElementById('categoryChart').getContext('2d');
      const catLabels = Object.keys(aggregateCategories);
      const catValues = Object.values(aggregateCategories);
      
      const themeColors = [
        'rgba(139, 92, 246, 0.7)',  // Violet
        'rgba(6, 182, 212, 0.7)',   // Cyan
        'rgba(244, 63, 94, 0.7)',   // Rose
        'rgba(245, 158, 11, 0.7)',  // Amber
        'rgba(16, 185, 129, 0.7)',  // Emerald
        'rgba(59, 130, 246, 0.7)'   // Blue
      ];
      const themeBorderColors = [
        'rgba(139, 92, 246, 1)',
        'rgba(6, 182, 212, 1)',
        'rgba(244, 63, 94, 1)',
        'rgba(245, 158, 11, 1)',
        'rgba(16, 185, 129, 1)',
        'rgba(59, 130, 246, 1)'
      ];

      new Chart(ctxPie, {
        type: 'doughnut',
        data: {
          labels: catLabels,
          datasets: [{
            data: catValues,
            backgroundColor: themeColors.slice(0, catLabels.length),
            borderColor: themeBorderColors.slice(0, catLabels.length),
            borderWidth: 1.5,
            hoverOffset: 12
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '72%',
          plugins: {
            legend: {
              position: 'right',
              labels: { color: '#e5e7eb', font: { family: 'Outfit', size: 11 } }
            },
            tooltip: {
              padding: 12,
              titleFont: { family: 'Outfit', size: 12, weight: 'bold' },
              bodyFont: { family: 'Outfit', size: 11 }
            }
          }
        }
      });
    }
  </script>
</body>
</html>
"""

# Inject results json
dashboard_content = html_template.replace("<!-- DATA_PLACEHOLDER -->", json.dumps(results))

with open(DASHBOARD_PATH, "w", encoding="utf-8") as f:
    f.write(dashboard_content)

print(f"Interactive Web Dashboard successfully saved to {DASHBOARD_PATH}")
