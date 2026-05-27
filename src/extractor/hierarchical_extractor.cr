# src/extractor/hierarchical_extractor.cr
# Catseye Hierarchical Crystal AST Extractor
#
# Emits a nested JSON tree directly from the Crystal compiler's AST.
# This produces the same structure as CatseyeAST.t, enabling the OCaml
# crystal_mapper to build typed expression trees without heuristic reconstruction.
#
# Usage: crystal run src/extractor/hierarchical_extractor.cr -- <file.cr>
#
# Output: JSON object with type, name, line, and typed child nodes.
# Control flow (if/unless/case) emits nested then/else/when bodies.
#
# Backward compatible: the taint/security metadata is preserved via
# a post-processing pass that annotates nodes with taint/scent info.

require "compiler/crystal/syntax"
require "json"

# ── Taint sources (same as extractor.cr) ──────────────────────────────

TAINT_SOURCES = Set{
  "params", "gets", "request", "env", "ARGV", "STDIN",
  "user_input", "user_url", "user_id", "query", "url",
  "path", "cmd", "command", "input",
}

SCENT_SOURCES = Set{
  "password", "passwd", "pass", "api_key", "apikey", "api_secret",
  "secret_key", "access_token", "refresh_token", "auth_token",
  "session_token", "token", "secret", "credential", "credentials",
  "private_key", "email", "email_address", "ssn", "credit_card",
  "session_id", "cookie", "database_url", "db_password",
}

SANITIZERS = Set{
  "URI.parse", "URI.encode", "URI.decode",
  "Path.posix", "Path.basename", "Path.dirname",
  "String.strip", "String.trim",
  "Int.parse", "Float.parse",
  "Base64.encode", "Base64.strict_encode",
  "Shell.escape", "Shellwords.escape",
  "CGI.escape", "CGI.escapeHTML",
  "JSON.parse", "JSON.mapping",
  "SecureRandom", "Random::Secure",
}

# ── Helper methods ────────────────────────────────────────────────────

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

private def is_tainted?(name : String) : Bool
  TAINT_SOURCES.includes?(name) || SCENT_SOURCES.includes?(name)
end

private def is_sanitizer?(name : String) : Bool
  SANITIZERS.any? { |s| name.includes?(s) }
end

private def has_scent?(name : String) : Bool
  SCENT_SOURCES.any? { |s| name.includes?(s) }
end

private def format_arg_type(node : Crystal::ASTNode) : String
  case node
  when Crystal::StringLiteral, Crystal::NumberLiteral, Crystal::BoolLiteral,
    Crystal::NilLiteral, Crystal::SymbolLiteral, Crystal::CharLiteral
    "literal"
  when Crystal::Var, Crystal::InstanceVar
    "var"
  when Crystal::Call
    "call"
  else
    "unknown"
  end
end

private def format_arg_value(node : Crystal::ASTNode) : String
  case node
  when Crystal::StringLiteral   then node.value
  when Crystal::NumberLiteral   then node.value
  when Crystal::BoolLiteral     then node.value.to_s
  when Crystal::NilLiteral      then "nil"
  when Crystal::SymbolLiteral   then ":#{node.value}"
  when Crystal::CharLiteral     then node.value.to_s
  when Crystal::Var             then node.name
  when Crystal::InstanceVar     then node.name
  when Crystal::Call            then format_call_name(node)
  when Crystal::Path            then node.names.join("::")
  when Crystal::StringInterpolation then "<interpolation>"
  else                               node.to_s[0..80]
  end
end

# ── Hierarchical Visitor ─────────────────────────────────────────────

class CatseyeHierarchicalVisitor < Crystal::Visitor
  def initialize(@json : JSON::Builder)
  end

  # ── Top-level: Expressions (file body) ───────────────────────────

  def visit(node : Crystal::Expressions) : Bool
    @json.object do
      @json.field "type", "Expressions"
      @json.field "line", line_of(node)
      @json.field "children" do
        @json.array do
          node.expressions.each &.accept(self)
        end
      end
    end
    false
  end

  # ── Function definitions ─────────────────────────────────────────

  def visit(node : Crystal::Def) : Bool
    @json.object do
      @json.field "type", "def"
      @json.field "name", node.name
      @json.field "line", line_of(node)
      @json.field "args" do
        @json.array do
          node.args.each do |arg|
            @json.object do
              @json.field "arg_type", "var"
              @json.field "value", arg.name
              @json.field "field", arg.external_name || ""
            end
          end
        end
      end
      @json.field "body" do
        if body = node.body
          body.accept(self)
        else
          @json.object do
            @json.field "type", "Unit"
          end
        end
      end
    end
    false
  end

  # ── Control flow: if ─────────────────────────────────────────────

  def visit(node : Crystal::If) : Bool
    @json.object do
      @json.field "type", "if"
      @json.field "name", node.else ? "if_else" : "if"
      @json.field "line", line_of(node)
      @json.field "condition" do
        if cond = node.cond
          cond.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
      @json.field "then" do
        if then_body = node.then
          then_body.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
      @json.field "else" do
        if else_body = node.else
          else_body.accept(self)
        else
          @json.null
        end
      end
    end
    false
  end

  # ── Control flow: unless (negated if) ────────────────────────────

  def visit(node : Crystal::Unless) : Bool
    @json.object do
      @json.field "type", "unless"
      @json.field "line", line_of(node)
      @json.field "condition" do
        if cond = node.cond
          cond.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
      @json.field "then" do
        if then_body = node.then
          then_body.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
      @json.field "else" do
        if else_body = node.else
          else_body.accept(self)
        else
          @json.null
        end
      end
    end
    false
  end

  # ── Control flow: case ───────────────────────────────────────────

  def visit(node : Crystal::Case) : Bool
    @json.object do
      @json.field "type", "case"
      @json.field "line", line_of(node)
      @json.field "subject" do
        if cond = node.cond
          cond.accept(self)
        else
          @json.null
        end
      end
      @json.field "whens" do
        @json.array do
          node.whens.each &.accept(self)
        end
      end
      @json.field "else" do
        if else_body = node.else
          else_body.accept(self)
        else
          @json.null
        end
      end
    end
    false
  end

  # ── Control flow: when (case branch) ────────────────────────────

  def visit(node : Crystal::When) : Bool
    @json.object do
      @json.field "type", "when"
      @json.field "line", line_of(node)
      @json.field "patterns" do
        @json.array do
          node.conds.each &.accept(self)
        end
      end
      @json.field "body" do
        if body = node.body
          body.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
    end
    false
  end

  # ── Method calls ─────────────────────────────────────────────────

  def visit(node : Crystal::Call) : Bool
    @json.object do
      @json.field "type", "call"
      @json.field "name", format_call_name(node)
      @json.field "line", line_of(node)
      # Taint/sanitizer metadata
      name_for_taint = node.name
      if is_tainted?(name_for_taint) || has_scent?(name_for_taint)
        @json.field "taint", true
        @json.field "scent", has_scent?(name_for_taint)
      end
      if is_sanitizer?(format_call_name(node))
        @json.field "sanitizer", true
      end
      @json.field "obj" do
        if obj = node.obj
          obj.accept(self)
        else
          @json.null
        end
      end
      @json.field "args" do
        @json.array do
          node.args.each do |arg|
            @json.object do
              @json.field "arg_type", format_arg_type(arg)
              @json.field "value", format_arg_value(arg)
            end
          end
        end
      end
    end
    false
  end

  # ── Assignments ──────────────────────────────────────────────────

  def visit(node : Crystal::Assign) : Bool
    @json.object do
      @json.field "type", "assign"
      @json.field "name", node.target.to_s
      @json.field "line", line_of(node)
      if is_tainted?(node.target.to_s)
        @json.field "taint", true
      end
      if has_scent?(node.target.to_s)
        @json.field "scent", true
      end
      @json.field "value" do
        node.value.accept(self)
      end
    end
    false
  end

  # Instance var assign: @x = ...
  def visit(node : Crystal::InstanceVar) : Bool
    @json.object do
      @json.field "type", "instance_var"
      @json.field "name", node.name
      @json.field "line", line_of(node)
    end
    false
  end

  # ── Variable references ─────────────────────────────────────────

  def visit(node : Crystal::Var) : Bool
    @json.object do
      @json.field "type", "var"
      @json.field "name", node.name
      if is_tainted?(node.name)
        @json.field "taint", true
      end
      if has_scent?(node.name)
        @json.field "scent", true
      end
    end
    false
  end

  # ── Literals ─────────────────────────────────────────────────────

  def visit(node : Crystal::StringLiteral) : Bool
    @json.object do
      @json.field "type", "literal"
      @json.field "value", node.value
      @json.field "literal_type", "string"
    end
    false
  end

  def visit(node : Crystal::NumberLiteral) : Bool
    @json.object do
      @json.field "type", "literal"
      @json.field "value", node.value
      @json.field "literal_type", "number"
    end
    false
  end

  def visit(node : Crystal::BoolLiteral) : Bool
    @json.object do
      @json.field "type", "literal"
      @json.field "value", node.value.to_s
      @json.field "literal_type", "bool"
    end
    false
  end

  def visit(node : Crystal::NilLiteral) : Bool
    @json.object do
      @json.field "type", "literal"
      @json.field "value", "nil"
      @json.field "literal_type", "nil"
    end
    false
  end

  def visit(node : Crystal::SymbolLiteral) : Bool
    @json.object do
      @json.field "type", "literal"
      @json.field "value", ":#{node.value}"
      @json.field "literal_type", "symbol"
    end
    false
  end

  def visit(node : Crystal::ArrayLiteral) : Bool
    @json.object do
      @json.field "type", "array"
      @json.field "line", line_of(node)
      @json.field "elements" do
        @json.array do
          node.elements.each &.accept(self)
        end
      end
    end
    false
  end

  def visit(node : Crystal::HashLiteral) : Bool
    @json.object do
      @json.field "type", "hash"
      @json.field "line", line_of(node)
      @json.field "entries" do
        @json.array do
          node.entries.each do |entry|
            @json.object do
              @json.field "key" do
                entry.key.accept(self)
              end
              @json.field "value" do
                entry.value.accept(self)
              end
            end
          end
        end
      end
    end
    false
  end

  # ── String interpolation ─────────────────────────────────────────

  def visit(node : Crystal::StringInterpolation) : Bool
    @json.object do
      @json.field "type", "interpolation"
      @json.field "line", line_of(node)
      @json.field "parts" do
        @json.array do
          node.expressions.each &.accept(self)
        end
      end
    end
    false
  end

  # ── Control flow terminators ─────────────────────────────────────

  def visit(node : Crystal::Return) : Bool
    @json.object do
      @json.field "type", "return"
      @json.field "line", line_of(node)
      @json.field "value" do
        if exp = node.exp
          exp.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
    end
    false
  end

  def visit(node : Crystal::Raise) : Bool
    @json.object do
      @json.field "type", "raise"
      @json.field "line", line_of(node)
      @json.field "value" do
        if exp = node.exp
          exp.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
    end
    false
  end

  # ── Exception handling ──────────────────────────────────────────

  def visit(node : Crystal::ExceptionHandler) : Bool
    @json.object do
      @json.field "type", "exception_handler"
      @json.field "line", line_of(node)
      @json.field "body" do
        if body = node.body
          body.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
      @json.field "rescues" do
        @json.array do
          if rescues = node.rescues
            rescues.each &.accept(self)
          end
        end
      end
      @json.field "else" do
        if else_body = node.else
          else_body.accept(self)
        else
          @json.null
        end
      end
      @json.field "ensure" do
        if ensure_body = node.ensure
          ensure_body.accept(self)
        else
          @json.null
        end
      end
    end
    false
  end

  def visit(node : Crystal::Rescue) : Bool
    @json.object do
      @json.field "type", "rescue"
      @json.field "line", line_of(node)
      @json.field "body" do
        if body = node.body
          body.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
    end
    false
  end

  # ── Class / Module / Struct ──────────────────────────────────────

  def visit(node : Crystal::ClassDef) : Bool
    @json.object do
      @json.field "type", "class"
      @json.field "name", node.name.to_s
      @json.field "line", line_of(node)
      @json.field "body" do
        if body = node.body
          body.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
    end
    false
  end

  def visit(node : Crystal::ModuleDef) : Bool
    @json.object do
      @json.field "type", "module"
      @json.field "name", node.name.to_s
      @json.field "line", line_of(node)
      @json.field "body" do
        if body = node.body
          body.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
    end
    false
  end

  def visit(node : Crystal::StructOrUnionDef) : Bool
    @json.object do
      @json.field "type", "struct"
      @json.field "name", node.name.to_s
      @json.field "line", line_of(node)
    end
    false
  end

  # ── Enum ─────────────────────────────────────────────────────────

  def visit(node : Crystal::EnumDef) : Bool
    @json.object do
      @json.field "type", "enum"
      @json.field "name", node.name.to_s
      @json.field "line", line_of(node)
      @json.field "members" do
        @json.array do
          node.members.each do |member|
            member.accept(self)
          end
        end
      end
    end
    false
  end

  # ── Require / Import ────────────────────────────────────────────

  def visit(node : Crystal::Require) : Bool
    @json.object do
      @json.field "type", "import"
      @json.field "name", "require"
      @json.field "line", line_of(node)
      @json.field "args" do
        @json.array do
          @json.object do
            @json.field "arg_type", "literal"
            @json.field "value", node.string
          end
        end
      end
    end
    false
  end

  # ── Const / Type Alias ────────────────────────────────────────────

  def visit(node : Crystal::Const) : Bool
    @json.object do
      @json.field "type", "const"
      @json.field "name", node.name.to_s
      @json.field "line", line_of(node)
    end
    false
  end

  def visit(node : Crystal::TypeDef) : Bool
    @json.object do
      @json.field "type", "type_def"
      @json.field "name", node.name.to_s
      @json.field "line", line_of(node)
    end
    false
  end

  # ── Path (type/module reference) ────────────────────────────────

  def visit(node : Crystal::Path) : Bool
    @json.object do
      @json.field "type", "path"
      @json.field "name", node.names.join("::")
    end
    false
  end

  # ── Block (do...end) ────────────────────────────────────────────

  def visit(node : Crystal::Block) : Bool
    @json.object do
      @json.field "type", "block"
      @json.field "line", line_of(node)
      @json.field "args" do
        @json.array do
          node.args.each do |arg|
            @json.object do
              @json.field "arg_type", "var"
              @json.field "value", arg.name
            end
          end
        end
      end
      @json.field "body" do
        if body = node.body
          body.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
    end
    false
  end

  # ── While / Loop ────────────────────────────────────────────────

  def visit(node : Crystal::While) : Bool
    @json.object do
      @json.field "type", "while"
      @json.field "line", line_of(node)
      @json.field "condition" do
        if cond = node.cond
          cond.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
      @json.field "body" do
        if body = node.body
          body.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
    end
    false
  end

  def visit(node : Crystal::Until) : Bool
    @json.object do
      @json.field "type", "until"
      @json.field "line", line_of(node)
      @json.field "condition" do
        if cond = node.cond
          cond.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
      @json.field "body" do
        if body = node.body
          body.accept(self)
        else
          @json.object { @json.field "type", "Unit" }
        end
      end
    end
    false
  end

  # ── Catch-all: generic AST node ─────────────────────────────────

  def visit(node : Crystal::ASTNode) : Bool
    @json.object do
      @json.field "type", node.class.name.split("::").last.underscore
      @json.field "line", line_of(node)
      @json.field "unmapped", true
    end
    true
  end

  private def line_of(node : Crystal::ASTNode) : Int32
    node.location.try(&.line_number) || 0
  end
end

# ── CLI Entry Point ──────────────────────────────────────────────────

if ARGV.size < 1
  STDERR.puts "Usage: catseye_hierarchical_extractor <source_file.cr>"
  exit 1
end

source_file = ARGV[0]
source_code = File.read(source_file)

begin
  parser = Crystal::Parser.new(source_code)
  top_node = parser.parse

  json_output = JSON.build do |json|
    visitor = CatseyeHierarchicalVisitor.new(json)
    top_node.accept(visitor)
  end

  puts json_output
  STDOUT.flush
rescue ex : Crystal::SyntaxException
  puts({"type" => "ParseError", "message" => ex.message.to_s, "line" => ex.line_number}.to_json)
  STDOUT.flush
  exit 1
rescue ex : Exception
  puts({"type" => "ParseError", "message" => ex.message.to_s, "line" => 0}.to_json)
  STDOUT.flush
  exit 1
end
