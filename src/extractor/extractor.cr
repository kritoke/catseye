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
}

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

# ── Security Node collector ────────────────────────────────────────────

alias SecNode = NamedTuple(
  type: String,
  name: String,
  args: Array(ArgNode),
  line: Int32,
  taint: Bool,
  file: String)

class SecurityVisitor < Crystal::Visitor
  getter nodes : Array(SecNode)
  @file_path : String
  # Track variable assignments to propagate taint
  @tainted_vars : Set(String)

  def initialize(@file_path : String)
    @nodes = [] of SecNode
    @tainted_vars = Set(String).new
  end

  def visit(node : Crystal::ASTNode) : Bool
    true
  end

  # ── Method definitions ─────────────────────────────────────────────

  def visit(node : Crystal::Def) : Bool
    @nodes << {
      type:  "def",
      name:  node.name,
      args:  node.args.map { |a| {arg_type: "var", value: a.name, field: ""} },
      line:  location_line(node),
      taint: false,
      file:  @file_path,
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

    if tainted
      @tainted_vars << target_name
    end

    @nodes << {
      type:  "assign",
      name:  target_name,
      args:  [classify_arg(node.value)],
      line:  location_line(node),
      taint: tainted,
      file:  @file_path,
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

    @nodes << {
      type:  "call",
      name:  call_name,
      args:  node.args.map { |a| classify_arg(a) },
      line:  location_line(node),
      taint: tainted,
      file:  @file_path,
    }
    true
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

  puts visitor.nodes.to_json
rescue ex : Crystal::SyntaxException
  STDERR.puts "Parse error in #{file_path}: #{ex.message}"
  puts "[]"
rescue ex : Exception
  STDERR.puts "Error processing #{file_path}: #{ex.message}"
  puts "[]"
end
