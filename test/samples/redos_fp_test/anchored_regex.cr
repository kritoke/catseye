# Minimal repro of the ReDoS FP: Regex.new with anchored alternation (&|$)
# Original from /workspaces/quickheadlines/src/utils/url_normalizer.cr:106.
# The (&|$) anchor provides a natural stop boundary; the rule's
# check_args_contain patterns (e.g. "+)+") are not in the pattern.

module UrlNormalizer
  TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign"}

  def self.normalize_query(query : String) : String
    return "" if query.empty?
    cleaned = query.gsub("dummy", "")
    tracking_pattern = Regex.new("#{TRACKING_PARAMS.join("|")}=?(&|$)", Regex::Options::IGNORE_CASE)
    cleaned.gsub(tracking_pattern, "")
  end
end
