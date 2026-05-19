/// Test 07: Alias and union analysis targets
use std::ptr;

// C-style union — should trigger ALIAS_UNION001
union CStyleUnion {
    int_val: i32,
    float_val: f32,
    bytes: [u8; 4],
}

union AnotherUnion {
    ptr: *mut u8,
    val: u64,
}

// Struct with multiple pointers to same type — should trigger ALIAS_STR001
struct DoublePointer {
    read: *const u8,
    write: *mut u8,
}

struct TripleMut {
    a: *mut i32,
    b: *mut i32,
    c: *mut i32,
}

struct MixedPointers {
    p1: *const f64,
    p2: *const f64,
    p3: *mut f64,
}

// Function with multiple *mut params of same type — should trigger ALIAS_FN001
unsafe fn aliased_write(a: *mut i32, b: *mut i32) {
    *a = *b;
}

unsafe fn triple_alias(x: *mut u8, y: *mut u8, z: *mut u8) {
    *x = *y;
    *y = *z;
}

// Mixed *const and *mut of same type — should trigger ALIAS_FN002
unsafe fn read_write_alias(src: *const i32, dst: *mut i32) {
    *dst = *src;
}

fn main() {
    let mut a = 1i32;
    let mut b = 2i32;
    unsafe {
        aliased_write(&mut a, &mut b);
        read_write_alias(&a, &mut b);
    }
}
