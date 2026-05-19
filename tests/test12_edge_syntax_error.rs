/// Test 12: Syntax error — should trigger AST000
fn broken_function( {
    let x = ;
    if true {
    // missing closing brace
}
