# Minimal repro of the UnboundedRead FP on `read_body_safe`.
# The KDL rule `UnboundedRead` has `sink "read" arg=0` matched by substring
# (`interpreter.ml:matches_sink -> is_substring`), so the call name
# `read_body_safe` matches because "read" is a substring of it.
#
# Original from:
#   /workspaces/quickheadlines/src/controllers/api_base_controller.cr:216
#   /workspaces/quickheadlines/src/controllers/header_color_controller.cr:12
# Helper defined at /workspaces/quickheadlines/src/utils.cr:93-115.
#
# The `read_body_safe` helper below IS the size-limited reader: it reads IO
# in 8KB chunks with an explicit max_size guard and raises IO::EOFError if
# the body exceeds max_size. The fixture reproduces the FP because the
# call site (`read_body_safe(body)`) is the only top-level call the
# extractor emits; helper body calls (`io.read`, `io.read_byte`) are
# not separately emitted at this level.
#
# Pre-fix: 1 UnboundedRead finding on line ~46.
# Post-fix (after adding `sanitizer "read_body_safe"`): 0 findings.

module QuickHeadlines
  module Constants
    MAX_REQUEST_BODY_SIZE = 1_048_576  # 1MB
    BUFFER_SIZE           = 8_192      # 8KB
  end

  def self.read_body_safe(io : IO, max_size : Int32 = Constants::MAX_REQUEST_BODY_SIZE) : String
    buffer = IO::Memory.new
    buffer_bytes = Bytes.new(Constants::BUFFER_SIZE)
    bytes_copied = 0

    while bytes_copied < max_size
      bytes_read = io.read(buffer_bytes)
      break if bytes_read == 0
      buffer.write(buffer_bytes[0, bytes_read])
      bytes_copied += bytes_read
    end

    if bytes_copied >= max_size && io.read_byte
      raise IO::EOFError.new("Request body exceeds #{max_size} bytes")
    end

    buffer.to_s
  end

  class BodyReader
    def handle(body : IO) : String
      content = read_body_safe(body)
      content
    end
  end
end
