/// Test 06: Ownership graph analysis targets
struct Resource {
    data: Vec<u8>,
}

impl Resource {
    fn new() -> Self {
        Self { data: vec![1, 2, 3] }
    }
}

fn excessive_cloning() {
    let r = Resource::new();
    let a = r.data.clone();
    let b = r.data.clone();
    let c = r.data.clone();
    let d = r.data.clone();
    let e = r.data.clone();
}

fn double_from_raw() {
    let original = Box::new(vec![1, 2, 3]);
    let ptr = Box::into_raw(original);
    unsafe {
        let first = Box::from_raw(ptr);
        let second = Box::from_raw(ptr); // double-free!
        // Both first and second will try to free the same memory
    }
}

fn forgotten_raw() {
    let b = Box::new(42);
    let raw = Box::into_raw(b);
    // raw is never re-boxed — memory leak
}

fn move_then_use() {
    let data = String::from("hello");
    let moved = data;
    // println!("{}", data); // would be use-after-move
}

fn main() {
    excessive_cloning();
    double_from_raw();
    forgotten_raw();
}
