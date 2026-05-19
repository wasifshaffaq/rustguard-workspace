/// Test 04: AST analyzer targets
use std::mem;

static mut COUNTER: u64 = 0;
static mut FLAG: bool = false;

struct EmptyStruct;
impl EmptyStruct {}

struct PtrStruct {
    a: *mut u8,
    b: *const u32,
    c: *mut f64,
}

fn too_many_params(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32) -> i32 {
    a + b + c + d + e + f + g + h
}

unsafe fn dangerous_function() {
    let x: i32 = 42;
    let y: u32 = mem::transmute(x);
    let z: f32 = mem::transmute(y);
    let w: i32 = mem::transmute(z);
    let a = Box::new(100);
    let ptr = Box::into_raw(a);
    let _ = Box::from_raw(ptr);
}

fn uses_unwrap() {
    let val: Option<i32> = Some(42);
    let x = val.unwrap();
    let s = "hello".parse::<i32>().unwrap();
}

fn uses_clone() {
    let data = vec![1, 2, 3];
    let a = data.clone();
    let b = data.clone();
    let c = data.clone();
    let d = data.clone();
}

fn main() {
    too_many_params(1, 2, 3, 4, 5, 6, 7, 8);
    uses_unwrap();
    uses_clone();
    unsafe { dangerous_function(); }
}
