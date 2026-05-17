# Hub-like class - should trigger warning (14+ dependencies)
class ApplicationCoordinator
  def initialize
    @http_client = HTTP::Client.new
    @db = DB::Connection.new
    @cache = Redis::Cache.new
    @logger = Logger::Log.new
    @config = Config::Loader.new
    @email = Email::Service.new
    @sms = SMS::Gateway.new
    @analytics = Analytics::Tracker.new
    @storage = Storage::S3.new
    @queue = Queue::Redis.new
    @cache2 = Cache::Memcached.new
    @search = Search::Elastic.new
    @queue2 = Queue::RabbitMQ.new
  end
  
  def handle(request)
    # Uses many dependencies
    HTTP::Client.get(request.url)
    DB::Connection.query("SELECT *")
    Redis::Cache.get("key")
    Logger::Log.info("message")
    Config::Loader.load("path")
    Email::Service.send("to")
    Search::Elastic.query("query")
  end
end
