/// Test 17: Performance patterns
fn empty_strings() {
    let a = String::from("");
    let b = String::from("");
    let c = String::from("");
}

fn c_style_loops() {
    let items = vec![1, 2, 3, 4, 5];
    for i in 0..items.len() {
        println!("{}", items[i]);
    }
    let names = vec!["a", "b", "c"];
    for i in 0..names.len() {
        println!("{}", names[i]);
    }
}

fn excessive_clone() {
    let big_data = vec![0u8; 10000];
    let c1 = big_data.clone();
    let c2 = big_data.clone();
    let c3 = big_data.clone();
}

fn todo_markers() {
    // TODO: implement caching
    // FIXME: this is slow
    // XXX: hack
}

fn main() {
    empty_strings();
    c_style_loops();
    excessive_clone();
}
