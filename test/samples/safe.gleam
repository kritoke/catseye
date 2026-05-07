// test/samples/safe.gleam
// Safe Gleam code — should produce zero findings

import gleam/io

pub fn fetch_homepage() {
  // Safe: hardcoded URL
  hackney.get("https://example.com")
}

pub fn safe_fetch() {
  // Safe: hardcoded URL passed directly
  hackney.get("https://api.example.com/v1/status")
}

pub fn compute(x: Int, y: Int) {
  x + y
}

pub fn greet() {
  io.println("Hello!")
}
