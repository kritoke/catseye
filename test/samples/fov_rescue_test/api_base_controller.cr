require "athena"
require "../constants"
require "../utils"
require "../dtos/config_dto"
require "../dtos/api_responses"
require "../web/assets"
require "../services/story_service"
require "../services/feed_service"
require "../services/clustering_service"
require "../repositories/feed_repository"
require "../repositories/story_repository"
require "../repositories/cluster_repository"
require "../websocket"
require "../rate_limiter"

class QuickHeadlines::Controllers::ApiBaseController < Athena::Framework::Controller
  @db_service : DatabaseService
  @feed_cache : FeedCache
  @socket_manager : SocketManager
  @clustering_service : QuickHeadlines::Services::ClusteringService?

  def self.new : self
    db = DatabaseService.instance
    cache = FeedCache.instance
    sm = SocketManager.instance
    new(db, cache, sm)
  end

  def initialize(@db_service : DatabaseService, @feed_cache : FeedCache, @socket_manager : SocketManager)
  end

  private def check_admin_auth(request : AHTTP::Request) : Bool
    secret = ENV["ADMIN_SECRET"]?

    # Fail loudly in development if ADMIN_SECRET is not configured
    # This helps catch misconfigurations early instead of silently denying access
    if secret.nil? || secret.empty?
      if ENV["APP_ENV"] == "development"
        Log.for("quickheadlines.auth").error { "ADMIN_SECRET not configured! Set ADMIN_SECRET environment variable for admin endpoints to work." }
      else
        Log.for("quickheadlines.auth").warn { "Admin auth attempt without ADMIN_SECRET configured from #{client_ip(request)}" } if has_auth_header?(request)
      end
      return false
    end

    auth_header = request.headers["Authorization"]?
    return false unless auth_header

    unless auth_header.starts_with?("Bearer ")
      return false
    end

    token = auth_header[7..-1]
    timing_safe_compare(secret, token)
  rescue ArgumentError
    false
  end

  private def has_auth_header?(request : AHTTP::Request) : Bool
    request.headers["Authorization"]?.try(&.starts_with?("Bearer ")) || false
  end

  private def check_rate_limit!(request : AHTTP::Request, key : String, max_requests : Int32, window_seconds : Int32) : Nil
    ip = client_ip(request)
    limiter_key = "#{key}:#{ip}"
    return if RateLimiter.allowed?(limiter_key, max_requests, window_seconds)
    retry_after = RateLimiter.retry_after(limiter_key, window_seconds)
    headers = HTTP::Headers{"Retry-After" => retry_after.to_s}
    raise AHK::Exception::HTTPException.new(429, "Rate limit exceeded", nil, headers)
  end

  private def client_ip(request : AHTTP::Request) : String
    extract_client_ip(request)
  end

  # Validate proxy URL and return resolved IP to prevent DNS rebinding.
  # Returns {valid, ip_address} where ip_address is the resolved IP for pinning.

end
