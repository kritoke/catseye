# Simple test for RefusedParentBequest

class Base
  def foo
  end
  
  def bar
  end
end

# Empty override - should be flagged
class Child < Base
  def foo
  end
end

# Another class to bound Child's end
class Other
  def test
  end
end