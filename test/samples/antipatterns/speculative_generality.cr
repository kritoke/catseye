# SpeculativeGenerality test case
# An abstract class with fewer than 2 children

abstract class AbstractBase
  def base; end
end

# Only 1 child - should trigger SpeculativeGenerality
class SingleChild < AbstractBase
  def child; end
end
