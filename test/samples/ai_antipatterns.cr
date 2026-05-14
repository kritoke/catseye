# test/samples/ai_antipatterns.cr
# Crystal code with AI anti-patterns for testing ai_linter rules

require "http/client"

# Rule 1.1: Hallucinated stdlib method (to_map doesn't exist)
def process_data(items)
  items.to_map { |x| x.id }
end

# Rule 1.1: String.join doesn't exist (it's Array.join)
def join_names(names)
  String.join(names, ", ")
end

# Rule 1.2: puts/p/pp for debugging (deprecated debug syntax)
def debug_user(user)
  puts "User: #{user.name}"
  p user.email
end

# Rule 2.3: Primitive obsession (3+ String params)
def create_record(name : String, email : String, phone : String, address : String, country : String)
  # AI often misses domain types
end

# Rule 4.1: Redundant String.new
def make_string
  String.new("hello")
end

class ApiClient
  # Rule 1.2: puts in class (debugging)
  def initialize(url)
    puts "Connecting to: #{url}"
  end
  
  # Rule 2.3: Many string params
  def send_email(from : String, to : String, subject : String, body : String, reply_to : String)
  end
end