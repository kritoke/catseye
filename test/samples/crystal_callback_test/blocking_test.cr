# This should trigger sequential-blocking (3+ HTTP calls)
def fetch_user_data(user_id)
  response1 = HTTP::Client.get("https://api.example.com/users/#{user_id}")
  response2 = HTTP::Client.get("https://api.example.com/posts?user_id=#{user_id}")
  response3 = HTTP::Client.get("https://api.example.com/comments?user_id=#{user_id}")
  combine_responses(response1, response2, response3)
end

# This should NOT trigger (only 2 calls)
def fetch_two(url1, url2)
  HTTP::Client.get(url1)
  HTTP::Client.get(url2)
end
