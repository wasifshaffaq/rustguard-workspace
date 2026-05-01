use std::ptr;

static mut GLOBAL: i32 = 0;

union DataRepr {
    int_val: i32,
    float_val: f32,
}

pub struct AliasedBuf {
    read_ptr: *const u8,
    write_ptr: *mut u8,
    meta_ptr: *mut u8,
}

pub fn unsafe_encapsulated(p: *mut i32) -> i32 {
    unsafe { *p }
}

pub fn aliased_fn(a: *mut i32, b: *mut i32) -> i32 {
    unsafe { *a + *b }
}

pub fn use_after_move() {
    let data = vec![1, 2, 3];
    let moved = data;
    println!("{:?}", data); // use after move
}

pub fn taint_flow(ptr: *mut u8, idx: usize) -> u8 {
    unsafe {
        let val = *ptr.add(idx);
        *ptr.add(val as usize) // tainted index
    }
}

fn main() {
    let v = vec![1u8, 2, 3];
    unsafe {
        let x = v.get_unchecked(0);
    }
}