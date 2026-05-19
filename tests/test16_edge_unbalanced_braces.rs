/// Test 16: Unbalanced braces — should trigger STRUCT001
fn open_brace() {
    {
        {
            let x = 1;
        }
    // missing closing brace
