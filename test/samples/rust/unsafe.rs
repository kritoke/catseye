// Intentional unsafe patterns in Rust
// These are common anti-patterns in AI-generated code

fn unwrap_examples() {
    // unwrap() without proper error handling
    let result: Result<i32, &str> = Ok(42);
    let value = result.unwrap();  // Could panic
    
    let option: Option<String> = Some("hello".to_string());
    let val = option.unwrap();  // Could panic
    
    // expect() - same issue
    let data = std::fs::read_to_string("config.txt").unwrap();  // Could panic
    let num = "42".parse::<i32>().unwrap();  // Could panic on invalid input
}

fn panic_examples() {
    // panic!() in production code
    panic!("This should not happen");
    
    // panic in a loop
    for item in items {
        if item.is_invalid() {
            panic!("Found invalid item");
        }
    }
    
    // expect() with generic message
    let config = load_config().expect("config required");
}

fn inefficient_code() {
    // Unnecessary clone
    let s1 = String::from("hello");
    let s2 = String::from(&s1);  // Should use s1.clone() or just &s1
    
    let data = vec![1, 2, 3];
    let copy = data.clone();
    let another = data.clone();  // Multiple unnecessary clones
    
    // Creating owned String from &str unnecessarily
    let text = "static";
    let owned = String::from(text);  // Should just use text
}

fn main() {
    unwrap_examples();
    panic_examples();
    inefficient_code();
}
