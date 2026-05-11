# src/extractor/extractor.cr
# Catseye Crystal AST Extractor
#
# Parses a .cr file using Crystal::Parser and visits Call + Assign nodes,
# emitting a JSON array of Security Node objects to stdout.
#
# Usage: crystal run src/extractor/extractor.cr -- <file.cr>

require "compiler/crystal/syntax"
require "json"

# ── Argument classification ────────────────────────────────────────────

alias ArgNode = NamedTuple(arg_type: String, value: String, field: String)

private def classify_arg(node : Crystal::ASTNode) : ArgNode
  case node
  when Crystal::StringLiteral
    {arg_type: "literal", value: node.value, field: ""}
  when Crystal::NumberLiteral
    {arg_type: "literal", value: node.value, field: ""}
  when Crystal::BoolLiteral
    {arg_type: "literal", value: node.value.to_s, field: ""}
  when Crystal::NilLiteral
    {arg_type: "literal", value: "nil", field: ""}
  when Crystal::SymbolLiteral
    {arg_type: "literal", value: ":#{node.value}", field: ""}
  when Crystal::Var
    {arg_type: "var", value: node.name, field: ""}
  when Crystal::InstanceVar
    {arg_type: "var", value: node.name, field: ""}
  when Crystal::Path
    {arg_type: "var", value: node.names.join("::"), field: ""}
  when Crystal::Call
    # Detect field access: params["url"] → field="url"
    field = extract_field(node)
    {arg_type: "call", value: format_call_name(node), field: field}
  when Crystal::StringInterpolation
    {arg_type: "call", value: "<interpolation>", field: ""}
  else
    {arg_type: "unknown", value: node.to_s[0..80], field: ""}
  end
end

# Extract field name from indexer calls: params["url"] → "url"
private def extract_field(node : Crystal::ASTNode) : String
  case node
  when Crystal::Call
    if node.name == "[]"
      # First arg is the key: params["url"] → "url"
      if node.args.size > 0
        case key = node.args.first
        when Crystal::StringLiteral
          key.value
        when Crystal::SymbolLiteral
          key.value
        else
          ""
        end
      else
        ""
      end
    else
      ""
    end
  else
    ""
  end
end

private def format_call_name(call : Crystal::Call) : String
  if obj = call.obj
    obj_name = case obj
               when Crystal::Var         then obj.name
               when Crystal::Path        then obj.names.join("::")
               when Crystal::InstanceVar then obj.name
               when Crystal::Call        then format_call_name(obj)
               else                           obj.to_s[0..40]
               end
    "#{obj_name}.#{call.name}"
  else
    call.name
  end
end

# ── Taint sources ──────────────────────────────────────────────────────

TAINT_SOURCES = Set{
  "params",
  "gets",
  "request",
  "env",
  "ARGV",
  "STDIN",
  "user_input",
  "user_url",
  "user_id",
  "query",
  "url",
  "path",
  "cmd",
  "command",
  "input",
}

SANITIZERS = Set{
  "URI.parse", "URI.encode", "URI.decode",
  "Path.posix", "Path.basename", "Path.dirname",
  "String.strip", "String.trim", "String.slice",
  "Int.parse", "Float.parse",
  "Digest::MD5.hexdigest", "Digest::SHA256.hexdigest",
  "Base64.encode", "Base64.strict_encode",
  "File.expand_path",
  "OpenSSL::Digest",
  "favicon_hash_for_url",
  "favicon_hash",
  # Guard patterns — validation that makes values safe
  "matches?", "starts_with?",
}

private def sanitize_call?(node : Crystal::ASTNode) : Bool
  return false unless node.is_a?(Crystal::Call)
  name = format_call_name(node)
  SANITIZERS.includes?(name) ||
    name.starts_with?("validate_") ||
    name.starts_with?("sanitize_") ||
    name.starts_with?("escape_") ||
    name.starts_with?("encode_") ||
    name.starts_with?("hash_for") ||
    name.includes?("hexdigest") ||
    name.includes?("hexstring")
end

private def tainted?(node : Crystal::ASTNode) : Bool
  case node
  when Crystal::Var
    TAINT_SOURCES.includes?(node.name)
  when Crystal::Call
    # If the call name itself is a taint source
    TAINT_SOURCES.includes?(node.name) ||
      # Or if the receiver is tainted (e.g., params["url"])
      (node.obj.try { |obj| tainted?(obj) } || false)
  when Crystal::InstanceVar
    TAINT_SOURCES.includes?(node.name)
  when Crystal::StringInterpolation
    # Only tainted if any interpolated *expression* is tainted
    # "hello #{name}" with safe name → not tainted
    # "git clone #{repo}" with tainted repo → tainted
    node.expressions.any? { |expr| tainted?(expr) }
  else
    false
  end
end

private def sanitizer_call?(node : Crystal::ASTNode) : Bool
  case node
  when Crystal::Call
    SANITIZERS.includes?(format_call_name(node))
  else
    false
  end
end

# ── SQL parameterized query detection ────────────────────────────────

# DB method patterns that execute SQL
DB_SINK_METHODS = Set{
  "query", "query_one?", "query_one", "query_all",
  "exec", "execute", "scalar",
}

# Check if a call is a DB method (receiver.name matches pattern)
private def db_call?(call : Crystal::Call) : Bool
  return false unless call.obj
  DB_SINK_METHODS.includes?(call.name)
end

# Check if the first argument of a DB call is a parameterized query.
# A parameterized query uses ? placeholders for all dynamic values.
private def parameterized_query?(first_arg : Crystal::ASTNode) : Bool
  case first_arg
  when Crystal::StringLiteral
    # Static SQL string — always safe (no dynamic content)
    # Even if it has no ?, it's a literal string with no user input
    true
  when Crystal::StringInterpolation
    # Check: do all interpolated expressions resolve to safe values?
    # "SELECT * FROM feeds WHERE url = ?" → safe (all static fragments)
    # "SELECT * FROM #{table}" → unsafe (dynamic table name)
    first_arg.expressions.all? { |expr|
      case expr
      when Crystal::StringLiteral, Crystal::NumberLiteral then true
      else false
      end
    }
  else
    false
  end
end

alias SecNode = NamedTuple(
  type: String,
  name: String,
  args: Array(ArgNode),
  line: Int32,
  taint: Bool,
  file: String,
  language: String,
  metadata: Hash(String, String)?)

class SecurityVisitor < Crystal::Visitor
  getter nodes : Array(SecNode)
  @file_path : String
  # Track variable assignments to propagate taint
  @tainted_vars : Set(String)
  # Track variables assigned from safe query interpolations (only ? + literals)
  @safe_query_vars : Set(String)

  def initialize(@file_path : String)
    @nodes = [] of SecNode
    @tainted_vars = Set(String).new
    @safe_query_vars = Set(String).new
  end

  def visit(node : Crystal::ASTNode) : Bool
    true
  end

  # ── Method definitions ─────────────────────────────────────────────

  def visit(node : Crystal::Def) : Bool
    @nodes << {
      type:     "def",
      name:     node.name,
      args:     node.args.map { |a| {arg_type: "var", value: a.name, field: ""} },
      line:     location_line(node),
      taint:    false,
      file:     @file_path,
      language: "crystal",
      metadata: nil,
    }
    true # visit body
  end

  # ── Assignments ────────────────────────────────────────────────────

  def visit(node : Crystal::Assign) : Bool
    target_name = case target = node.target
                  when Crystal::Var         then target.name
                  when Crystal::InstanceVar then target.name
                  else                           target.to_s[0..60]
                  end

    tainted = tainted?(node.value)

    # Propagate taint: if RHS references a tainted variable
    if !tainted && (var_node = node.value.as?(Crystal::Var))
      tainted = @tainted_vars.includes?(var_node.name)
    end

    # Sanitizer calls cleanse taint: filename = Path.basename(input) → not tainted
    # Also remove from @tainted_vars if reassigned through a sanitizer
    if sanitizer_call?(node.value)
      tainted = false
      @tainted_vars.delete(target_name)
    end

    # Track safe query variables: assigned from string interpolation
    # that only contains literals (e.g., "SELECT ... IN (#{placeholders})" where
    # placeholders was built from .map { "?" })
    if !tainted
      if interp = node.value.as?(Crystal::StringInterpolation)
        if interp.expressions.all? { |expr|
          case expr
          when Crystal::StringLiteral, Crystal::NumberLiteral then true
          else false
          end
        }
          @safe_query_vars << target_name
        end
      elsif str_node = node.value.as?(Crystal::StringLiteral)
        # Variable assigned from a static string — safe query source
        @safe_query_vars << target_name
      end
    end

    if tainted
      @tainted_vars << target_name
    end

    @nodes << {
      type:     "assign",
      name:     target_name,
      args:     [classify_arg(node.value)],
      line:     location_line(node),
      taint:    tainted,
      file:     @file_path,
      language: "crystal",
      metadata: nil,
    }
    true
  end

  # ── Method calls ───────────────────────────────────────────────────

  def visit(node : Crystal::Call) : Bool
    call_name = format_call_name(node)
    tainted = false

    # Check if any argument is tainted
    node.args.each do |arg|
      if tainted?(arg)
        tainted = true
        break
      end
      # Check if arg is a variable we've marked as tainted
      if var_node = arg.as?(Crystal::Var)
        if @tainted_vars.includes?(var_node.name)
          tainted = true
          break
        end
      end
      # Check if arg is a string interpolation with tainted vars
      if interp = arg.as?(Crystal::StringInterpolation)
        has_tainted = interp.expressions.any? do |expr|
          (var_node = expr.as?(Crystal::Var)) && @tainted_vars.includes?(var_node.name)
        end
        if has_tainted
          tainted = true
          break
        end
      end
    end

    # Detect guard patterns: hash.matches?(...) or path.starts_with?(...)
    # When a validation method is called on a variable, mark it as guarded/safe
    if node.name == "matches?" || node.name == "starts_with?" || node.name == "in?"
      if obj = node.obj
        case obj
        when Crystal::Var
          @tainted_vars.delete(obj.name)
          @safe_query_vars << obj.name
        end
      end
    end

    # Detect parameterized SQL queries
    metadata : Hash(String, String)? = nil
    if db_call?(node) && node.args.size > 0
      if parameterized_query?(node.args.first)
        metadata = {"parameterized_query" => "true"}
      else
        # Check if first arg is a safe query variable
        case first_arg = node.args.first
        when Crystal::Var
          if @safe_query_vars.includes?(first_arg.name)
            metadata = {"parameterized_query" => "true"}
          end
        end
        # Check if call uses named args: parameter (args: values)
        # Crystal's DB API uses named args for bound parameters
        if node.named_args && node.named_args.try &.any?(&.name.in?("args", "params"))
          metadata = {"parameterized_query" => "true"}
        end
      end
    end

    @nodes << {
      type:     "call",
      name:     call_name,
      args:     node.args.map { |a| classify_arg(a) },
      line:     location_line(node),
      taint:    tainted,
      file:     @file_path,
      language: "crystal",
      metadata: metadata,
    }
    true
  end

  # ── Timeout configuration tracking ───────────────────────────────

  # Timeout property setters: client.read_timeout = , client.connect_timeout = etc.
  TIMEOUT_SETTERS = Set{
    "read_timeout",
    "write_timeout",
    "connect_timeout",
  }

  # Post-process: mark HTTP::Client.new calls as having timeout config
  # if they're followed by timeout-setting calls within 5 lines on the same variable.
  def self.annotate_timeouts(nodes : Array(SecNode)) : Array(SecNode)
    # Build map: variable name → list of (line, is_http_client, is_timeout_setter, is_timeout_helper)
    client_vars = Set(String).new
    timeout_configured = Set(String).new
    # Track (file, def_line) pairs where HTTP::Client.new appears
    # for scope-based timeout detection (handles .tap blocks)
    http_client_defs = Set(Tuple(String, Int32)).new
    # Track (file, def_line) pairs where timeout setters appear
    timeout_setter_defs = Set(Tuple(String, Int32)).new

    # Build def scope map: for each node, find its enclosing def line
    def_scopes = {} of Tuple(String, Int32) => Int32
    current_def = {} of String => Int32
    nodes.each do |n|
      if n[:type] == "def"
        current_def[n[:file]] = n[:line]
      end
      if current_def[n[:file]]?
        def_scopes[{n[:file], n[:line]}] = current_def[n[:file]]
      end
    end

    nodes.each do |n|
      case n[:type]
      when "assign"
        # Track HTTP client variable assignments
        if n[:args].any? &.[:value].includes?("HTTP::Client.new")
          client_vars << n[:name]
          scope = def_scopes[{n[:file], n[:line]}]?
          http_client_defs << {n[:file], scope} if scope
        end
      when "call"
        # Track HTTP::Client.new calls (even without assign, e.g. in .tap chain)
        if n[:name].includes?("HTTP::Client.new")
          scope = def_scopes[{n[:file], n[:line]}]?
          http_client_defs << {n[:file], scope} if scope
        end
        # Detect timeout property setters: client.read_timeout=(value)
        if n[:name].includes?("=") && n[:name].includes?(".")
          parts = n[:name].split(".")
          if parts.size == 2
            var_name = parts[0]
            method = parts[1].rchop # remove trailing =
            if TIMEOUT_SETTERS.includes?(method)
              timeout_configured << var_name if client_vars.includes?(var_name)
              # Also track scope-based: any timeout setter in same def as HTTP::Client.new
              scope = def_scopes[{n[:file], n[:line]}]?
              timeout_setter_defs << {n[:file], scope} if scope
            end
          end
        end
        # Detect timeout helper methods: apply_default_timeouts(client)
        if n[:name].includes?("apply_default_timeouts") ||
           n[:name].includes?("configure_timeouts")
          n[:args].each do |arg|
            if arg[:arg_type] == "var" && client_vars.includes?(arg[:value])
              timeout_configured << arg[:value]
            end
          end
        end
      end
    end

    # Now annotate the HTTP::Client.new call nodes
    nodes.map do |n|
      if n[:type] == "call" && n[:name].includes?("HTTP::Client.new")
        # Find which variable this was assigned to by checking subsequent assigns
        var_name = find_assign_target(nodes, n[:line], n[:file])
        has_var_timeout = var_name && timeout_configured.includes?(var_name)
        # Also check scope-based: same def has timeout setters
        scope = def_scopes[{n[:file], n[:line]}]?
        has_scope_timeout = scope && timeout_setter_defs.includes?({n[:file], scope})

        if has_var_timeout || has_scope_timeout
          {
            type:     n[:type],
            name:     n[:name],
            args:     n[:args],
            line:     n[:line],
            taint:    n[:taint],
            file:     n[:file],
            language: n[:language],
            metadata: {"has_timeout_config" => "true"},
          }
        else
          n
        end
      else
        n
      end
    end
  end

  private def self.find_assign_target(nodes : Array(SecNode), call_line : Int32, file : String) : String?
    # Look for an assignment on the same line or next line that captures the HTTP::Client.new result
    nodes.each do |n|
      if n[:type] == "assign" && n[:file] == file &&
         (n[:line] == call_line || n[:line] == call_line + 1)
        if n[:args].any? &.[:value].includes?("HTTP::Client.new")
          return n[:name]
        end
      end
    end
    nil
  end

  private def location_line(node : Crystal::ASTNode) : Int32
    loc = node.location
    loc ? loc.line_number : 0
  end
end

# ── Main ───────────────────────────────────────────────────────────────

if ARGV.size < 1
  STDERR.puts "Usage: crystal run extractor.cr -- <file.cr>"
  exit 1
end

file_path = ARGV[0]

unless File.file?(file_path)
  STDERR.puts "Error: file not found: #{file_path}"
  exit 1
end

begin
  source = File.read(file_path)
  parser = Crystal::Parser.new(source)
  parser.filename = file_path
  ast = parser.parse

  visitor = SecurityVisitor.new(file_path)
  ast.accept(visitor)

  # Post-process: annotate timeout configuration on HTTP::Client.new nodes
  annotated = SecurityVisitor.annotate_timeouts(visitor.nodes)

  puts annotated.to_json
rescue ex : Crystal::SyntaxException
  STDERR.puts "Parse error in #{file_path}: #{ex.message}"
  puts "[]"
rescue ex : Exception
  STDERR.puts "Error processing #{file_path}: #{ex.message}"
  puts "[]"
end
