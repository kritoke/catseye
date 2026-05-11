# Copy-paste block B — same structure as dry_a.cr with renamed variables
# Expected: MEOW DRYViolation (structural duplicate of dry_a.cr)

def fetch_item(id)
  endpoint = params["endpoint"]
  response = HTTP:: Client.get(endpoint)
  parsed = JSON.parse(response)
  item = parsed["item"]
  puts item
end
