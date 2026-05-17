# Test case for Feature Envy (Shotgun Surgery smell)
# This class heavily uses methods from Logger, so behavior should be in Logger

class FeatureEnvyExample
  @logger : Logger
  @config : Config

  def initialize(@logger, @config)
  end

  def process_data(data)
    # Multiple calls to Logger - this behavior belongs in Logger
    @logger.info("Starting process")
    @logger.info("Processing item 1")
    @logger.info("Processing item 2")
    @logger.info("Processing item 3")
    @logger.info("Processing item 4")
    @logger.info("Processing item 5")
    @logger.info("Finished processing")
    
    # Multiple calls to Config
    @config.get("host")
    @config.get("port")
    @config.get("timeout")
    @config.get("retry_count")
    @config.get("debug")
    
    data
  end

  def another_method(data)
    @logger.debug("Debug message 1")
    @logger.debug("Debug message 2")
    @logger.debug("Debug message 3")
    @logger.debug("Debug message 4")
    @logger.debug("Debug message 5")
    @logger.debug("Debug message 6")
    
    data.upcase
  end
end

# This should NOT trigger - it's a facade/exempt class
class SomeFacade
  def orchestrate
    Logger.info("1")
    Logger.info("2")
    Logger.info("3")
    Logger.info("4")
    Logger.info("5")
    Logger.info("6")
  end
end