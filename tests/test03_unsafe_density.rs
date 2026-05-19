/// Test 03: Extreme unsafe density — should trigger DENSE001
unsafe fn op1() -> i32 { 42 }
unsafe fn op2() -> i32 { unsafe { op1() } }
unsafe fn op3(p: *mut i32) { *p = unsafe { op2() }; }
unsafe fn op4(a: *mut i32, b: *mut i32) { *a = *b; }
unsafe fn op5(p: *mut i32) -> i32 { unsafe { *p } }
unsafe fn op6() { let mut x = 0i32; unsafe { op3(&mut x as *mut i32) }; }
unsafe fn op7() { unsafe { op6(); op6(); } }
unsafe fn op8(p: *const i32) -> i32 { unsafe { *p } }
unsafe fn op9() { let x = 42i32; unsafe { op8(&x as *const i32); } }
unsafe fn op10() { unsafe { op7(); op9(); } }
