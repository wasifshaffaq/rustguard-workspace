/// Test 08: Cross-function semantic analysis targets
use std::ptr;

// Public safe fn calling unsafe fn — should trigger CROSS_001
unsafe fn internal_unsafe_op(p: *mut i32) -> i32 {
    *p
}

pub fn public_safe_facade(val: &mut i32) -> i32 {
    unsafe { internal_unsafe_op(val as *mut i32) }
}

// Public fn returning raw pointer — should trigger CROSS_002
pub fn allocate_buffer(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

// Public safe fn taking raw pointer — should trigger CROSS_003
pub fn process_raw(ptr: *mut i32, len: usize) {
    unsafe {
        for i in 0..len {
            *ptr.add(i) = 0;
        }
    }
}

// Recursive unsafe function — should trigger CROSS_004
pub unsafe fn recursive_unsafe(p: *mut i32, depth: usize) -> i32 {
    if depth == 0 {
        return *p;
    }
    *p += 1;
    recursive_unsafe(p, depth - 1)
}

// Allocates and returns raw ptr with no cleanup — should trigger CROSS_005
pub unsafe fn create_resource() -> *mut [u8; 1024] {
    Box::into_raw(Box::new([0u8; 1024]))
}

fn main() {
    let mut val = 42;
    let result = public_safe_facade(&mut val);
    println!("Result: {}", result);
}
