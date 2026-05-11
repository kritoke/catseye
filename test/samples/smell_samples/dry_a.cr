# Copy-paste block A — duplicated logic from dry_b.cr
# Expected: MEOW DRYViolation (found in both files)

def fetch_user(id)
  url = params["url"]
  result = HTTP::Client.get(url)
  data = JSON.parse(result)
  user = data["user"]
  puts user
end
