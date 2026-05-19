/// Test 05: Data-flow taint analysis targets
use std::ptr;

fn safe_wrapper(p: *mut i32) -> i32 {
    // Unsafe encapsulation: safe fn wrapping unsafe block
    unsafe { *p }
}

fn tainted_index(ptr: *mut u8, len: usize) -> u8 {
    unsafe {
        let idx = *ptr; // idx is tainted from raw ptr deref
        let arr = [0u8; 256];
        arr[idx as usize] // tainted value used as index
    }
}

fn null_deref_risk() {
    let p: *mut i32 = std::ptr::null_mut();
    unsafe {
        let val = *p; // deref of null ptr without check
    }
}

fn double_box_from_raw() {
    let b = Box::new(42);
    let raw = Box::into_raw(b);
    unsafe {
        let b1 = Box::from_raw(raw);
        let b2 = Box::from_raw(raw); // double free!
    }
}

fn static_lifetime_hallucination(data: &'static str) -> &'static str {
    data
}

fn get_unchecked_usage() {
    let v = vec![1, 2, 3, 4, 5];
    unsafe {
        let x = v.get_unchecked(10); // out of bounds
    }
}

fn main() {
    let mut x = 42;
    safe_wrapper(&mut x as *mut i32);
}
