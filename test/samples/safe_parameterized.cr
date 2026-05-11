# test/samples/safe_parameterized.cr
# Safe Crystal SQL patterns — should produce 0 SQL injection findings

class SafeQueries
  def find_by_url(db, url : String)
    # Safe: static SQL with ? placeholder
    db.query_one?("SELECT * FROM feeds WHERE url = ?", url)
  end

  def find_by_id(db, id : Int64)
    # Safe: static SQL with multiple ? placeholders
    db.query("SELECT title, link FROM items WHERE feed_id = ? AND pub_date > ?", id, "2024-01-01")
  end

  def update_feed(db, title : String, id : Int64)
    # Safe: all dynamic values are bound via ?
    db.exec("UPDATE feeds SET title = ? WHERE id = ?", title, id)
  end

  def batch_insert(db, items : Array(String))
    # Safe: placeholders generated from .map — only ? characters
    placeholders = items.map { "?" }.join(", ")
    query = "SELECT link FROM items WHERE link IN (#{placeholders})"
    db.query(query, args: items)
  end

  def delete_all(db)
    # Safe: no dynamic content at all
    db.exec("DELETE FROM items")
  end

  def count_feeds(db)
    # Safe: no user input in query
    db.scalar("SELECT COUNT(*) FROM feeds")
  end
end
