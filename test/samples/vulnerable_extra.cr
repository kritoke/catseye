# test/samples/vulnerable_extra.cr
# Test samples for additional vulnerability rules

require "http/client"

# Open Redirect
class RedirectController
  def do_redirect(params : Hash(String, String))
    dest = params["url"]
    redirect_to(dest)
  end

  def safe_redirect
    redirect_to("/home")
  end
end

# Insecure Deserialization
class DataHandler
  def parse_body(params : Hash(String, String))
    body = params["data"]
    _ = JSON.parse(body)
  end
end

# LDAP Injection
class AuthService
  def find_user(params : Hash(String, String))
    username = params["username"]
    LDAP.search("(uid=#{username})")
  end
end

# Weak Cryptography
class CryptoUtil
  def self.hash_password(password : String)
    Digest::MD5.hexdigest(password)
  end

  def self.safe_hash(password : String)
    Digest::SHA256.hexdigest(password)
  end
end
