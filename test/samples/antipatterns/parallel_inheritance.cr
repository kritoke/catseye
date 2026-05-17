# Test case for Parallel Inheritance smell
# Two parallel hierarchies that must be kept in sync

# These two parent classes form a parallel hierarchy:
# When you add Circle, you must also add CircleRenderer

class Shape
  def area; end
  def perimeter; end
end

class Renderer
  def render; end
  def clear; end
end

# Shape hierarchy
class Circle < Shape
  def radius; end
end

class Square < Shape
  def side; end
end

# Renderer hierarchy (parallel to Shape)
class CircleRenderer < Renderer
  def draw_circle; end
end

class SquareRenderer < Renderer
  def draw_square; end
end