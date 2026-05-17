# BaseClassShouldBeAbstract test case
# A concrete class with 3+ subclasses should be abstract

class BaseController
  # Base functionality that all controllers need
  def base_action; end
end

class ChildController1 < BaseController
  def index; end
end

class ChildController2 < BaseController
  def show; end
end

class ChildController3 < BaseController
  def create; end
end
