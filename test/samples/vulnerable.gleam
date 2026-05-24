pub fn fetch_data(url) {
  let result = fetch(url)
  handle_result(result)
}

fn handle_result(result) {
  case result {
    Ok(data) -> process(data)
    Error(e) -> log_error(e)
  }
}

pub fn process(data) {
  // Security check
  if is_valid(data) {
    write_to_file(data)
  }
}
