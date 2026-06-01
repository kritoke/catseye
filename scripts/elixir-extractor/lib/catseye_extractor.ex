defmodule CatseyeExtractor do
  @moduledoc """
  Extracts AST information from Elixir codebases for Catseye analysis.
  Outputs JSON (one object per line) compatible with Catseye's AST representation.
  """

  # Sink patterns for taint analysis
  @ssrf_sinks [
    "HTTPoison.get",
    "HTTPoison.post",
    "HTTPoison.put",
    "HTTPoison.delete",
    "HTTPoison.patch",
    "HTTPoison.head",
    "HTTPoison.options",
    "Tesla.get",
    "Tesla.post",
    "Tesla.put",
    "Tesla.delete",
    "Tesla.patch",
    "Req.get",
    "Req.post",
    "Req.put",
    "Req.delete",
    "Req.patch",
    "Mint.HTTP.connect"
  ]

  @sql_sinks [
    "Ecto.Repo.all",
    "Ecto.Repo.one",
    "Ecto.Repo.get",
    "Repo.all",
    "Repo.one",
    "Repo.get",
    "Repo.query",
    "Ecto.Adapters.SQL.query"
  ]

  @xss_sinks [
    "Phoenix.HTML.raw",
    "raw",
    "content_tag"
  ]

  @code_exec_sinks [
    "Code.eval_string",
    "Code.eval",
    "Code.eval_quoted",
    "Kernel.eval"
  ]

  @doc """
  Run the extractor on all .ex/.exs files in lib/
  """
  def run do
    run_dir("lib")
  end

  @doc """
  Run the extractor on a specific directory
  """
  def run_dir(dir) when is_binary(dir) do
    exs_files = Path.wildcard(dir <> "/**/*.exs")
    ex_files = Path.wildcard(dir <> "/**/*.ex")
    all_files = Enum.concat([exs_files, ex_files])
    Enum.each(all_files, &run_file/1)
  end

  @doc """
  Run the extractor on a specific file
  """
  def run_file(file) when is_binary(file) do
    case File.read(file) do
      {:ok, content} ->
        case Code.string_to_quoted(content) do
          {:ok, ast} ->
            extract_module(file, ast)
            |> Jason.encode!()
            |> IO.puts()

          {:error, error} ->
            IO.puts(:stderr, "Error parsing #{file}: #{inspect(error)}")
        end

      {:error, error} ->
        IO.puts(:stderr, "Error reading #{file}: #{inspect(error)}")
    end
  end

  def extract_module(file, ast) do
    module_name = extract_module_name(ast)
    functions = extract_functions(ast)

    %{
      file: file,
      language: "elixir",
      module: module_name,
      functions: functions
    }
  end

  defp extract_module_name({:__MODULE__, _, _}), do: nil

  defp extract_module_name({:defmodule, _, [{:__aliases__, _, name_parts}, _]}) do
    Module.concat(name_parts) |> to_string()
  end

  defp extract_module_name(_), do: nil

  # Walk the AST recursively to collect function definitions
  defp extract_functions(ast) do
    find_defs(ast, [])
    |> Enum.reverse()
    |> Enum.reject(&is_nil/1)
  end

  defp find_defs({:def, _, [{:when, _, [{name, _, args}, _guard]}, body]}, acc)
       when is_atom(name) do
    [extract_function_body(name, args, body) | acc]
  end

  defp find_defs({:defp, _, [{:when, _, [{name, _, args}, _guard]}, body]}, acc)
       when is_atom(name) do
    [extract_function_body(name, args, body) | acc]
  end

  defp find_defs({:def, _, [{name, _, args}, body]}, acc) when is_atom(name) do
    [extract_function_body(name, args, body) | acc]
  end

  defp find_defs({:defp, _, [{name, _, args}, body]}, acc) when is_atom(name) do
    [extract_function_body(name, args, body) | acc]
  end

  # Skip defs where name is not a simple atom (e.g. unquote blocks, macro-generated)
  defp find_defs({:def, _, _}, acc), do: acc
  defp find_defs({:defp, _, _}, acc), do: acc

  defp find_defs(tuple, acc) when is_tuple(tuple) do
    tuple
    |> Tuple.to_list()
    |> Enum.reduce(acc, &find_defs/2)
  end

  defp find_defs(list, acc) when is_list(list) do
    Enum.reduce(list, acc, &find_defs/2)
  end

  defp find_defs(_, acc), do: acc

  # extract_function_body: atom name (normal case) must come BEFORE the catch-all
  defp extract_function_body(name, args, body) when is_atom(name) do
    params = extract_params(args)
    calls = extract_calls(body)
    sinks = Enum.filter(calls, &is_sink?/1)
    sources = extract_sources(body)
    line = extract_line(body)

    %{
      name: to_string(name),
      arity: length(params),
      params: params,
      line: line,
      calls: calls,
      sinks: sinks,
      sources: sources
    }
  end

  # Skip macro-generated defs where name is not a simple atom (e.g. unquote blocks)
  defp extract_function_body(_name, _args, _body), do: nil

  defp extract_params(nil), do: []

  defp extract_params(args) when is_list(args) do
    Enum.map(args, fn
      {var, _, _} when is_atom(var) -> to_string(var)
      {var, _, nil} when is_atom(var) -> to_string(var)
      {var, _, mod} when is_atom(var) and is_atom(mod) -> to_string(var)
      {:&, _, [num]} -> "_#{num}"
      _ -> "_"
    end)
  end

  defp extract_params(_), do: []

  defp extract_calls(ast) do
    find_calls(ast, [])
    |> Enum.reverse()
    |> Enum.reject(fn call -> call.name == "__block__" or call.name == "__aliases__" end)
  end

  defp find_calls({{:., meta, [{:__aliases__, _, parts}, fn_name]}, _, args}, acc) do
    clean_parts = Enum.filter(parts, &is_atom/1)

    module_name =
      if Enum.empty?(clean_parts),
        do: "",
        else: Module.concat(clean_parts) |> to_string() |> String.replace("Elixir.", "")

    full_name = if module_name == "", do: to_string(fn_name), else: "#{module_name}.#{fn_name}"
    call = %{name: full_name, line: meta[:line] || 0, args: extract_call_args(args)}
    # Recurse into args (e.g., fn blocks passed as arguments)
    Enum.reduce(args, [call | acc], &find_calls/2)
  end

  defp find_calls({{:., meta, [{:., _, [outer_mod, inner_name]}, fn_name]}, _, args}, acc) do
    # Handle nested modules like Outer.Inner.method
    outer_str = to_string(outer_mod) |> String.replace("Elixir.", "")
    full_name = "#{outer_str}.#{inner_name}.#{fn_name}"
    call = %{name: full_name, line: meta[:line] || 0, args: extract_call_args(args)}
    Enum.reduce(args, [call | acc], &find_calls/2)
  end

  defp find_calls({{:., meta, [mod, fn_name]}, _, args}, acc)
       when is_atom(mod) and is_atom(fn_name) do
    full_name = "#{mod}.#{fn_name}" |> String.replace("Elixir.", "")
    call = %{name: full_name, line: meta[:line] || 0, args: extract_call_args(args)}
    Enum.reduce(args, [call | acc], &find_calls/2)
  end

  # Recurse into keyword list bodies (e.g., [do: body], [do: ..., else: ...])
  # These are [{:key, value}, ...] tuples, not function calls
  defp find_calls({key, value}, acc) when is_atom(key) do
    find_calls(value, acc)
  end

  # Skip Elixir control-flow pseudo-calls — recurse into args
  @control_flow ~w(__block__ case try if cond with receive fn)a
  defp find_calls({fun, _meta, args}, acc) when is_atom(fun) and is_list(args) and fun in @control_flow do
    Enum.reduce(args, acc, &find_calls/2)
  end

  # Actual function call — capture it and recurse into args
  defp find_calls({fun, meta, args}, acc) when is_atom(fun) and is_list(args) do
    clean_name = to_string(fun) |> String.replace("Elixir.", "")
    call = %{name: clean_name, line: meta[:line] || 0, args: extract_call_args(args)}
    Enum.reduce(args, [call | acc], &find_calls/2)
  end

  defp find_calls(tuple, acc) when is_tuple(tuple) do
    Tuple.to_list(tuple) |> Enum.reduce(acc, &find_calls/2)
  end

  defp find_calls(list, acc) when is_list(list) do
    Enum.reduce(list, acc, &find_calls/2)
  end

  defp find_calls(_, acc), do: acc

  defp extract_call_args(args) when is_list(args) do
    args
    |> Enum.map(&macro_to_string/1)
    |> Enum.take(5)
  end

  defp extract_call_args(_), do: []

  defp macro_to_string({:__MODULE__, _, _}), do: "__MODULE__"
  defp macro_to_string({:__DIR__, _, _}), do: "__DIR__"
  defp macro_to_string({:__ENV__, _, _}), do: "__ENV__"
  defp macro_to_string({:conn, _, _}), do: "conn"
  defp macro_to_string({:params, _, _}), do: "params"
  defp macro_to_string({atom, _, nil}) when is_atom(atom), do: "#{atom}"

  defp macro_to_string({atom, _, mods}) when is_atom(atom) and is_list(mods) do
    # Only concat if it looks like module parts (atoms), not pipe operators
    if Enum.all?(mods, &is_atom/1) do
      Module.concat([atom | mods]) |> to_string()
    else
      to_string(atom)
    end
  end

  defp macro_to_string({op, _, [a, b]}) when op in [:+, :-, :*, :/],
    do: "#{macro_to_string(a)} #{op} #{macro_to_string(b)}"

  defp macro_to_string({op, _, [a, b]}) when op in [:++, :--, :<>],
    do: "#{macro_to_string(a)} #{op} #{macro_to_string(b)}"

  defp macro_to_string({op, _, [a, b]}) when op in [:==, :!=, :<, :>, :<=, :>=],
    do: "#{macro_to_string(a)} #{op} #{macro_to_string(b)}"

  defp macro_to_string({:., _, [a, b]}), do: "#{macro_to_string(a)}.#{macro_to_string(b)}"
  defp macro_to_string({:&, _, [num]}), do: "&#{num}"
  defp macro_to_string({:<<>>, _, args}), do: "<binary: #{length(args)} parts>"
  defp macro_to_string({:%{}, _, args}), do: "%{#{length(args)} fields}"
  defp macro_to_string({:|, _, [a, b]}), do: "#{macro_to_string(a)} | #{macro_to_string(b)}"
  defp macro_to_string(l) when is_list(l), do: "[#{length(l)} items]"

  defp macro_to_string(s) when is_binary(s) do
    suffix = if String.length(s) > 20, do: "...", else: ""
    "\"" <> String.slice(s, 0, 20) <> suffix <> "\""
  end

  defp macro_to_string(n) when is_integer(n), do: to_string(n)
  defp macro_to_string(n) when is_float(n), do: to_string(n)
  defp macro_to_string(a) when is_atom(a), do: ":#{a}"
  defp macro_to_string(nil), do: "nil"
  defp macro_to_string({:unquote, _, [arg]}), do: "unquote(#{macro_to_string(arg)})"
  defp macro_to_string({:quote, _, _}), do: "quote(...)"
  defp macro_to_string({:if, _, _}), do: "if (...)"
  defp macro_to_string({:case, _, _}), do: "case (...)"
  defp macro_to_string({:cond, _, _}), do: "cond"
  defp macro_to_string({:receive, _, _}), do: "receive"
  defp macro_to_string({:try, _, _}), do: "try (...)"
  defp macro_to_string({:with, _, _}), do: "with (...)"
  defp macro_to_string({:|, _, _}), do: "(pipe)"
  defp macro_to_string(_), do: "..."

  defp extract_sources(ast) do
    find_sources(ast, MapSet.new())
    |> MapSet.to_list()
  end

  defp find_sources({{:., _meta, [{:conn, _, _}, field]}, _, _}, acc)
       when field in [:params, :body, :query_params, :path_params, :req_headers, :resp_body] do
    MapSet.put(acc, "conn.#{field}")
  end

  defp find_sources(tuple, acc) when is_tuple(tuple) do
    Tuple.to_list(tuple) |> Enum.reduce(acc, &find_sources/2)
  end

  defp find_sources(list, acc) when is_list(list) do
    Enum.reduce(list, acc, &find_sources/2)
  end

  defp find_sources(_, acc), do: acc

  defp extract_line({:do, body}), do: extract_line(body)
  defp extract_line({_, meta, _}) when is_list(meta), do: meta[:line] || 0
  defp extract_line(_), do: 0

  defp is_sink?(%{name: name}) do
    # Strip "Elixir." prefix if present for cleaner comparison
    clean_name = name |> String.replace("~M", "") |> String.replace("Elixir.", "")

    Enum.any?(@ssrf_sinks, &String.contains?(clean_name, &1)) ||
      Enum.any?(@sql_sinks, &String.contains?(clean_name, &1)) ||
      Enum.any?(@xss_sinks, &String.contains?(clean_name, &1)) ||
      Enum.any?(@code_exec_sinks, &String.contains?(clean_name, &1))
  end
end
