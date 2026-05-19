/// Test 14: LLM hallucination patterns
use std::ptr;
use std::mem;

// LLM_PAT001: 'static everywhere
fn static_heavy(a: &'static str, b: &'static [u8]) -> &'static str {
    a
}

// LLM_PAT002: get_unchecked
fn unsafe_indexing(v: &[i32]) -> i32 {
    unsafe { *v.get_unchecked(0) + *v.get_unchecked_mut(1) }
}

// LLM_PAT003: Box::from_raw
fn box_from_raw_misuse() {
    let b = Box::new(String::from("hello"));
    let raw = Box::into_raw(b);
    unsafe {
        let _s1 = Box::from_raw(raw);
        let _s2 = Box::from_raw(raw); // double free hallucination
    }
}

// LLM_PAT004: ptr::drop_in_place
fn manual_drop(p: *mut String) {
    unsafe {
        ptr::drop_in_place(p);
    }
}

// LLM_PAT005: bare pointer casts
fn pointer_casts() {
    let x = 42i32;
    let p = &x as *const i32;
    let q = p as *mut i32;
    let r = q as *const i32;
}

// CVE_BUF001: ptr::copy
fn raw_memcpy(src: *const u8, dst: *mut u8, len: usize) {
    unsafe {
        ptr::copy(src, dst, len);
        ptr::copy_nonoverlapping(src, dst, len);
    }
}

// CVE_INT001: narrowing casts
fn narrow_casts(x: i64) {
    let a = x as i8;
    let b = x as u8;
    let c = x as i16;
    let d = x as u16;
}

// CONC001: Mutex unwrap
fn mutex_panic() {
    use std::sync::Mutex;
    let m = Mutex::new(42);
    let val = m.lock().unwrap();
}

// CONC002: Arc::clone
fn arc_usage() {
    use std::sync::Arc;
    let a = Arc::new(42);
    let b = Arc::clone(&a);
}

fn main() {}
