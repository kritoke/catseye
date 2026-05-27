defmodule CatseyeExtractor.CLI do
  @moduledoc """
  Command-line interface for the Catseye Elixir extractor.
  Provides a main/1 function for escript invocation.
  """

  def main(args) do
    case args do
      [] ->
        run_dir("lib")

      ["--help" | _] ->
        IO.puts("""
        CatseyeExtractor — Elixir AST extractor for Catseye analysis

        Usage:
          catseye_extractor             # Extract all .ex/.exs files in lib/
          catseye_extractor <dir>      # Extract all .ex/.exs files in <dir>
          catseye_extractor --help     # Show this help

        Output: JSON (one object per line), compatible with Catseye's AST format.
        """)

      ["--file", file | _opts] ->
        run_file(file)

      [dir | _opts] ->
        run_dir(dir)
    end
  end

  def run_file(file) when is_binary(file) do
    case File.read(file) do
      {:ok, content} ->
        case Code.string_to_quoted(content) do
          {:ok, ast} ->
            CatseyeExtractor.extract_module(file, ast)
            |> Jason.encode!()
            |> IO.puts()

          {:error, error} ->
            IO.puts(:stderr, "Error parsing #{file}: #{inspect(error)}")
        end

      {:error, error} ->
        IO.puts(:stderr, "Error reading #{file}: #{inspect(error)}")
    end
  end

  defp run_dir(dir) when is_binary(dir) do
    exs_files = Path.wildcard(dir <> "/**/*.exs")
    ex_files = Path.wildcard(dir <> "/**/*.ex")
    all_files = Enum.concat([exs_files, ex_files])
    Enum.each(all_files, &run_file/1)
  end
end
