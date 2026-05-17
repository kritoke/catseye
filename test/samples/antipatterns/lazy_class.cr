# Lazy class test case
# Classes with fewer than 3 methods should trigger LazyClass

# This is lazy - only 1 method (excluding initialize)
class EmptyService
  def process
    "doing something"
  end
end

# Still lazy - only 2 methods
class MiniProcessor
  def initialize(name : String)
    @name = name
  end

  def run
    @name.upcase
  end
end

# This is OK - 3 methods
class GoodProcessor
  def initialize(name : String)
    @name = name
  end

  def run
    @name.upcase
  end

  def reset
    @name = ""
  end
end

# Another lazy class
module Helpers
  def self.single_method
    puts "only one"
  end
end