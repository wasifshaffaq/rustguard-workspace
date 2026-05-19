/// Test 13: Huge function with massive unsafe block
fn megafn(
    a1: i32, a2: i32, a3: i32, a4: i32, a5: i32,
    a6: i32, a7: i32, a8: i32, a9: i32, a10: i32,
    a11: i32, a12: i32, a13: i32, a14: i32, a15: i32,
) -> i32 {
    unsafe {
        let mut sum = 0;
        sum += a1;
        sum += a2;
        sum += a3;
        sum += a4;
        sum += a5;
        sum += a6;
        sum += a7;
        sum += a8;
        sum += a9;
        sum += a10;
        sum += a11;
        sum += a12;
        sum += a13;
        sum += a14;
        sum += a15;
        sum
    }
}

fn main() {
    let r = megafn(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
    println!("{}", r);
}
