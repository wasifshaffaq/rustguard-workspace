/// Test 09: CVE retention testing (pair with test09_source.c)
use std::ptr;

fn buffer_copy_unsafe(src: *const u8, dst: *mut u8, len: usize) {
    unsafe {
        ptr::copy_nonoverlapping(src, dst, len); // CWE-120 retained
    }
}

fn integer_cast(big: i64) -> i16 {
    big as i16 // CWE-190: silent truncation
}

fn double_free_risk() {
    let b = Box::new(42);
    let raw = Box::into_raw(b);
    unsafe {
        let _ = Box::from_raw(raw);
        // If called again: double free
    }
}

fn null_pointer_usage() {
    let p: *mut i32 = std::ptr::null_mut();
    let val = unsafe { *p }; // null deref, no Option/NonNull
}

static mut SHARED_STATE: i32 = 0;

fn racy_increment() {
    unsafe {
        SHARED_STATE += 1; // CWE-362: race condition
    }
}

fn unchecked_access(data: &[u8], idx: usize) -> u8 {
    unsafe { *data.get_unchecked(idx) } // CWE-125: OOB
}

fn main() {
    let src = [1u8, 2, 3];
    let mut dst = [0u8; 3];
    buffer_copy_unsafe(src.as_ptr(), dst.as_mut_ptr(), 3);
    let small = integer_cast(100000);
    println!("{}", small);
}
