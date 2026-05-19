/// Test 15: Concurrency patterns
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

static mut GLOBAL_COUNTER: i64 = 0;
static mut ANOTHER_GLOBAL: bool = false;

fn thread_unsafe_increment() {
    unsafe {
        GLOBAL_COUNTER += 1;
        ANOTHER_GLOBAL = true;
    }
}

fn mutex_unwrap_usage() {
    let data = Arc::new(Mutex::new(vec![1, 2, 3]));
    let data_clone = Arc::clone(&data);
    
    let handle = thread::spawn(move || {
        let mut locked = data_clone.lock().unwrap(); // CONC001
        locked.push(4);
    });
    
    let mut main_lock = data.lock().unwrap(); // CONC001
    main_lock.push(5);
    handle.join().unwrap();
}

fn rwlock_unwrap_usage() {
    let data = Arc::new(RwLock::new(String::from("hello")));
    let reader = data.read().unwrap(); // CONC001
    let writer = data.write().unwrap(); // CONC001
}

fn main() {
    thread_unsafe_increment();
    mutex_unwrap_usage();
}
