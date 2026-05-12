# Test: guarded path traversal should NOT be flagged
def serve_file(path : String)
  # Guard: validates path prefix
  raise "invalid path" unless path.starts_with?("/safe/dir/")

  File.read(path)
end

# Test: unguarded path traversal SHOULD be flagged
def serve_file_unsafe(params : Hash(String, String))
  path = params["path"]
  File.read(path)
end
