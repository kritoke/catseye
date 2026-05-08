# test/samples/vulnerable_patterns.cr
# Test samples for enhanced pattern detection

# ReDoS: nested quantifiers in regex
EVIL_REGEX   = Regex.new("(a+)+")
ANOTHER_EVIL = Regex.new("([a-zA-Z]+)*")

# Safe regex
SAFE_REGEX = Regex.new("[a-z]+")

# Environment injection
def set_env(params : Hash(String, String))
  val = params["value"]
  ENV["PATH"] = val
end

# File.join path traversal
def serve_file(params : Hash(String, String))
  user_path = params["path"]
  full_path = File.join("uploads", user_path)
  File.read(full_path)
end
