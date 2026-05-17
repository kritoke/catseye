# DeepInheritance test case
# Classes with more than 4 levels of inheritance

class Level1
  def one; end
end

class Level2 < Level1
  def two; end
end

class Level3 < Level2
  def three; end
end

class Level4 < Level3
  def four; end
end

class Level5 < Level4
  def five; end
end

class Level6 < Level5
  def six; end
end
