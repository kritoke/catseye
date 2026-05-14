// test/samples/ai_antipatterns.gleam
// Gleam code with AI anti-patterns for testing ai_linter rules

import gleam/io

// Rule: List.wrap on collection is unnecessary
pub fn wrap_list(items) {
  List.wrap(items)
}

// Rule: Result.is_ok/is_err deprecated
pub fn check_result(result) {
  Result.is_ok(result)
}

// Rule: Todo in code
pub fn process_user(user) {
  let name = todo
  name
}

// Rule: Panic call
pub fn risky_operation() {
  panic
}

// Rule: Hallucinated _or_default function
pub fn get_value(map) {
  map.get_or_default("key", "default")
}

// Rule: Hallucinated to_list
pub fn convert_data(data) {
  data.to_list()
}

// Rule: TypeScript interface (wrong keyword)
pub fn create_interface() {
  interface User {
    name: String
  }
}

// Rule: Non-exhaustive case (simulated with Result handling)
pub fn handle_response(response) {
  case response of
    Ok(value) -> value
    // Missing Error branch!
}