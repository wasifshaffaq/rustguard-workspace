/// Test 19: False positive testing
/// These patterns LOOK like issues but are actually safe/intentional

// 'static is correct here — string literals ARE 'static
fn returns_static_str() -> &'static str {
    "hello world"
}

// unwrap is fine on known-good values
fn safe_unwrap() {
    let x: Option<i32> = Some(42);
    let y = x.unwrap(); // this is fine — we know it's Some
    
    let s = "42".parse::<i32>().unwrap(); // known valid
}

// clone() is necessary here — can't borrow
fn necessary_clone() {
    let data = String::from("hello");
    let handle = std::thread::spawn(move || {
        println!("{}", data);
    });
}

// Arc::clone is the correct pattern
fn correct_arc_usage() {
    let shared = Arc::new(vec![1, 2, 3]);
    let clone1 = Arc::clone(&shared);
    let clone2 = Arc::clone(&shared);
}

use std::sync::Arc;

fn main() {
    returns_static_str();
    safe_unwrap();
}
