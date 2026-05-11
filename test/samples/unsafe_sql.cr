# test/samples/unsafe_sql.cr
# Genuinely unsafe Crystal SQL patterns — should produce SQL injection findings

class UnsafeQueries
  def query_by_table(db, table : String)
    # UNSAFE: dynamic table name from user input
    db.query("SELECT * FROM #{table}")
  end

  def raw_query(db, user_input : String)
    # UNSAFE: user input directly in query string
    query = "SELECT * FROM feeds WHERE url = '#{user_input}'"
    db.query(query)
  end
end
