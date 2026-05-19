// Test file for Gleam 'use' expression handling

import gleam/io

// Test 1: Basic use - value should be used in body
pub fn basic_use(result) {
  use value <- validate(result)
  io.debug(value)
}

// Test 2: Unused use binding - should be flagged
pub fn unused_use(result) {
  use value <- validate(result)
  io.debug("done")
}

// Test 3: Multiple use expressions
pub fn chained_use(a, b, c) {
  use x <- step1(a)
  use y <- step2(b)
  use z <- step3(c)
  x + y + z
}

// Test 4: Nested use in block
pub fn nested_use() {
  let data = Ok(42)
  use val <- process(data)
  case val > 0 {
    True -> val * 2
    False -> 0
  }
}
