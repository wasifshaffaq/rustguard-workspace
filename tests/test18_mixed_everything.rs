/// Test 18: Kitchen sink — every issue type combined
use std::ptr;
use std::mem;
use std::sync::{Arc, Mutex};

static mut GLOBAL: i32 = 0;

union BadUnion {
    i: i32,
    f: f32,
}

struct AliasedPtrs {
    a: *mut u8,
    b: *mut u8,
    c: *const u8,
}

impl AliasedPtrs {}

pub unsafe fn dangerous_api(a: *mut i32, b: *mut i32) -> *mut i32 {
    let val: u32 = mem::transmute(*a);
    *b = val as i16 as i32;
    let result = Box::into_raw(Box::new(*a + *b));
    result
}

pub fn safe_but_calls_unsafe(x: &mut i32) -> i32 {
    unsafe { dangerous_api(x as *mut i32, x as *mut i32) };
    x.clone();
    let v: Option<i32> = Some(42);
    v.unwrap()
}

fn llm_artifacts() {
    let data: &'static str = "hello";
    let v = vec![1, 2, 3];
    unsafe {
        let x = v.get_unchecked(0);
        let raw = Box::into_raw(Box::new(42));
        let b = Box::from_raw(raw);
        ptr::drop_in_place(raw);
        ptr::copy_nonoverlapping(data.as_ptr(), ptr::null_mut(), 5);
    }
    let big: i64 = 999999;
    let small = big as i8;
    
    // TODO: fix this
    unimplemented!()
}

fn c_style_code() {
    let items = vec![1, 2, 3];
    for i in 0..items.len() {
        println!("{}", items[i]);
    }
    let empty = String::from("");
    let m = Mutex::new(42);
    let val = m.lock().unwrap();
}

pub unsafe fn recursive_danger(p: *mut i32, n: usize) -> i32 {
    if n == 0 { return *p; }
    *p += 1;
    recursive_danger(p, n - 1)
}

fn main() {
    let mut x = 42;
    safe_but_calls_unsafe(&mut x);
    llm_artifacts();
    c_style_code();
}
