# Test file for callback pyramid detection

def fetch_all(id)
  # This should trigger callback-pyramid (3 levels of nesting)
  client.get("/users/#{id}") do |response|
    data = JSON.parse(response.body)
    data["items"].each do |item|
      process_item(item) do |result|
        puts result
      end
    end
  end
end

def nested_callbacks
  # 4 levels of nested blocks - definitely a pyramid
  Future.new do
    compute do |a|
      transform(a) do |b|
        store(b) do |c|
          c
        end
      end
    end
  end
end

def acceptable_depth
  # Only 2 levels - should NOT trigger (max_depth = 2)
  method1 do
    method2 do
      puts "ok"
    end
  end
end