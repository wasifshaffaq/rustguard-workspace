use std::ptr;

static mut COUNTER: i32 = 0;

struct Node {
    value: i32,
    next: *mut Node,
}

fn process_data(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32) -> i32 {
    let result = some_value.unwrap();
    let copy = data.clone();
    
    unsafe {
        let raw: *mut i32 = ptr::null_mut();
        let val = std::mem::transmute::<i32, u32>(42);
    }
    
    // TODO: implement properly
    let empty = String::from("");
    
    for i in 0..items.len() {
        println!("{}", i);
    }
    
    unimplemented!()
}