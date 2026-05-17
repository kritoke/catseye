# Normal class - should NOT trigger
class UserService
  def initialize(@db = DB::Connection.new)
  end
  
  def get_user(id)
    @db.query("SELECT * FROM users WHERE id = ?", id)
  end
end
