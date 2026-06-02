#!/usr/bin/env elixir
#
# Query the Facet Pi feedback database for Catseye improvement.
#
# Usage:
#   elixir scripts/feedback.exs [command] [db_path]
#
# Commands:
#   summary       Counts by detection type (default)
#   scans         Recent scan results (last 50)
#   fp            User-flagged false positives
#   missed        Issues Catseye didn't catch
#   new           New findings manually reported by users
#   json          Export all feedback as JSON
#   json <type>   Export feedback filtered by type as JSON
#
# Database defaults to $HOME/.facet-pi/feedback.db

Mix.install([{:exqlite, "~> 0.25"}, {:jason, "~> 1.2"}])

defmodule Feedback do
  alias Exqlite.Sqlite3

  @columns ~w(id timestamp file_path code_snippet detection_type tool_name issue_description user_notes)

  def run(args) do
    {cmd, filter, db} = parse_args(args)

    unless File.exists?(db) do
      IO.puts(:stderr, "No feedback database at #{db}")
      System.halt(1)
    end

    case cmd do
      :summary -> show_summary(db)
      :scans -> show_scans(db)
      :by_type -> show_by_type(db, filter)
      :json -> show_json(db, filter)
    end
  end

  defp parse_args(args) do
    db = System.get_env("FACET_DB") || Path.join(System.user_home!(), ".facet-pi/feedback.db")

    {db_overrides, rest} = Enum.split_with(args, &String.ends_with?(&1, ".db"))
    db = List.first(db_overrides, db)

    case rest do
      [] -> {:summary, nil, db}
      ["summary"] -> {:summary, nil, db}
      ["scans"] -> {:scans, nil, db}
      ["fp"] -> {:by_type, "false_positive", db}
      ["missed"] -> {:by_type, "missed_issue", db}
      ["new"] -> {:by_type, "new_finding", db}
      ["json"] -> {:json, nil, db}
      ["json", type] -> {:json, type, db}
      [unknown | _] ->
        IO.puts(:stderr, "Unknown command: #{unknown}")
        IO.puts(:stderr, "Available: summary, scans, fp, missed, new, json [type]")
        System.halt(1)
    end
  end

  defp connect(db) do
    case Sqlite3.open(db) do
      {:ok, conn} -> conn
      {:error, reason} ->
        IO.puts(:stderr, "Failed to open #{db}: #{inspect(reason)}")
        System.halt(1)
    end
  end

  defp query(conn, sql, params \\ []) do
    with {:ok, stmt} <- Sqlite3.prepare(conn, sql),
         :ok <- Sqlite3.bind(stmt, params),
         {:ok, rows} <- Sqlite3.fetch_all(conn, stmt) do
      rows
    else
      {:error, reason} ->
        IO.puts(:stderr, "Query failed: #{inspect(reason)}")
        System.halt(1)
    end
  end

  defp show_summary(db) do
    conn = connect(db)
    rows = query(conn, "SELECT detection_type, COUNT(*) as count FROM feedback GROUP BY detection_type ORDER BY count DESC")

    Enum.each(rows, fn [type, count] ->
      IO.puts(String.pad_trailing(to_string(type), 20) <> to_string(count))
    end)

    Sqlite3.close(conn)
  end

  defp show_scans(db) do
    conn = connect(db)
    rows = query(conn, "SELECT id, tool_name, file_path, issue_description, user_notes FROM feedback WHERE detection_type = 'scan_result' ORDER BY id DESC LIMIT 50")

    IO.puts(String.pad_leading("ID", 4) <> "  " <> String.pad_trailing("Tool", 12) <> "  " <> String.pad_trailing("File", 41) <> "  " <> String.pad_trailing("Description", 61) <> "  Notes")
    IO.puts(String.duplicate("-", 160))

    Enum.each(rows, fn [id, tool, file, desc, notes] ->
      IO.puts(
        String.pad_leading(to_string(id), 4) <> "  " <>
        String.pad_trailing(tool || "", 12) <> "  " <>
        String.pad_trailing(String.slice(file || "", 0, 40), 41) <> "  " <>
        String.pad_trailing(String.slice(desc || "", 0, 60), 61) <> "  " <>
        (notes || "")
      )
    end)

    Sqlite3.close(conn)
  end

  defp show_by_type(db, type) do
    conn = connect(db)
    rows = query(conn, "SELECT id, tool_name, file_path, issue_description, user_notes FROM feedback WHERE detection_type = ? ORDER BY id DESC", [type])

    Enum.each(rows, fn [id, tool, file, desc, notes] ->
      IO.puts("##{id} [#{tool}] #{file}")
      IO.puts("  #{desc}")
      IO.puts("  Notes: #{notes}")
      IO.puts("")
    end)

    Sqlite3.close(conn)
  end

  defp show_json(db, nil) do
    conn = connect(db)
    rows = query(conn, "SELECT * FROM feedback ORDER BY id DESC")

    maps = Enum.map(rows, fn row -> Enum.zip(@columns, row) |> Map.new() end)
    IO.puts(Jason.encode!(maps, pretty: true))

    Sqlite3.close(conn)
  end

  defp show_json(db, type) do
    conn = connect(db)
    rows = query(conn, "SELECT * FROM feedback WHERE detection_type = ? ORDER BY id DESC", [type])

    maps = Enum.map(rows, fn row -> Enum.zip(@columns, row) |> Map.new() end)
    IO.puts(Jason.encode!(maps, pretty: true))

    Sqlite3.close(conn)
  end
end

Feedback.run(System.argv())
