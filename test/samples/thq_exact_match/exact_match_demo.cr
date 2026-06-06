# E2E fixture for the match="exact" KDL sink opt-in.
# This fixture is a smoke test: the unit tests in kdl_precision_test.ml
# cover the engine logic. The fixture exists to prove the field is parsed
# correctly through the full loader pipeline and produces no unintended
# findings in the post-fix engine.

module ExactMatchDemo
  # A function that, under bare substring matching, would have produced
  # false positives on names like "retry_after" or "try_rescue". With
  # match="exact" applied to the "try" sink in ocaml_error_context.kdl,
  # the rule no longer fires on these names.
  def self.demo_call(name : String) : String
    name
  end
end
