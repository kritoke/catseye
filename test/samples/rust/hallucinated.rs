// Intentional AI hallucinated function calls
// These patterns are common in AI-generated Rust code

fn main() {
    // Python patterns that don't exist in Rust
    let items = vec![1, 2, 3];
    let len = len(items);  // Should use .len()
    
    for i in range(0, 10) {  // Should use for i in 0..10
        println!("{}", i);
    }
    
    // dict/get pattern (Go/Ruby)
    let mut data = dict();
    let value = data.get("key");  // Should use HashMap::get()
    
    // JSON parsing (Python)
    let parsed = json.loads(data);  // Should use serde_json::from_str()
    
    // list operations
    let mut items = list();
    items.append(1);  // Should use Vec::push()
    
    // copy vs clone
    let copy = copy(data);  // Should use .clone()
}

fn process() {
    // Lambda (Python pattern)
    let func = lambda x: x + 1;  // Should use closures |x| x + 1
    
    // __init__ (Python class pattern)
    fn __init__() {}  // Should use fn new() -> Self
    
    // raise (Python exception)
    raise("error");  // Should use panic!() or return Err()
    
    // try/except (Python)
    try {
        let result = risky();
    } except {
        handle_error();
    }
}
