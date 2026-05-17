# Source file - taint is introduced here
def get_url
  params["url"]
end

# This URL should be tainted
def fetch_data(url)
  url  # return tainted url
end
