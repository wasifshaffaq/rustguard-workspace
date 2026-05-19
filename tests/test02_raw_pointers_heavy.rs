/// Test 02: Heavy raw pointer usage — should trigger RAW001, RAW002, multiple Memory issues
use std::ptr;

static mut GLOBAL_BUF: [u8; 1024] = [0u8; 1024];

struct LinkedList {
    head: *mut Node,
    tail: *mut Node,
}

struct Node {
    data: i32,
    next: *mut Node,
    prev: *mut Node,
}

unsafe fn create_node(val: i32) -> *mut Node {
    let node = Box::into_raw(Box::new(Node {
        data: val,
        next: ptr::null_mut(),
        prev: ptr::null_mut(),
    }));
    node
}

unsafe fn append(list: *mut LinkedList, val: i32) {
    let node = create_node(val);
    if (*list).tail.is_null() {
        (*list).head = node;
        (*list).tail = node;
    } else {
        (*(*list).tail).next = node;
        (*node).prev = (*list).tail;
        (*list).tail = node;
    }
}

unsafe fn free_list(list: *mut LinkedList) {
    let mut current = (*list).head;
    while !current.is_null() {
        let next = (*current).next;
        let _ = Box::from_raw(current);
        current = next;
    }
}

fn main() {
    unsafe {
        let mut list = LinkedList {
            head: ptr::null_mut(),
            tail: ptr::null_mut(),
        };
        append(&mut list as *mut LinkedList, 1);
        append(&mut list as *mut LinkedList, 2);
        append(&mut list as *mut LinkedList, 3);
        free_list(&mut list as *mut LinkedList);
    }
}
