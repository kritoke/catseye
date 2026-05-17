# TraditionBreaker test case
# A small class inheriting from a large parent

class RootController
  def root_action; end
end

class BaseController < RootController
  # Many methods to make this class "large"
  def index; end
  def show; end
  def new; end
  def create; end
  def edit; end
  def update; end
  def destroy; end
  def delete; end
end

class ConfigController < BaseController
  # Small child - only adds one method
  def config_only; end
end
