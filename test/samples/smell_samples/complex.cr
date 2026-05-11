# Function with high cyclomatic complexity (M=15)
# Expected: MEOW HighComplexity (warning threshold: 10)

def complex_function(x, y)
  if x > 0
    if y > 0
      if x > y
        puts "x wins"
      else
        puts "y wins"
      end
    else
      unless x == 0
        puts "x positive, y not"
      end
    end
  else
    case y
    when 1
      puts "one"
    when 2
      puts "two"
    when 3
      puts "three"
    else
      puts "other"
    end
  end
end
