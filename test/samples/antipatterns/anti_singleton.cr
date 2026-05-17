# Anti-Singleton test case
# Classes with mutable class variables should trigger AntiSingleton

class Counter
  # This is a mutable class variable - anti-pattern
  @@count = 0
  @@last_reset = Time.now

  def self.increment
    @@count += 1
  end

  def self.reset
    @@count = 0
  end
end

# Another class with class variables
class SessionManager
  @@current_user = nil
  @@cache = Hash(String, String).new

  def self.login(user)
    @@current_user = user
  end
end

# This class is fine - only instance variables
class GoodClass
  def initialize
    @value = 0
  end
end