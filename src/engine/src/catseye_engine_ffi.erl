-module(catseye_engine_ffi).

-export([read_stdin/0, decode_json/1, decode_input/1, encode_findings/1]).

%% ═══ Stdin ═════════════════════════════════════════════════════════════

read_stdin() ->
    read_stdin_acc(<<>>).

read_stdin_acc(Acc) ->
    case io:get_line("") of
        eof -> {ok, Acc};
        {error, _} -> {error, nil};
        Line when is_list(Line) -> read_stdin_acc(<<Acc/binary, (list_to_binary(Line))/binary>>);
        Line when is_binary(Line) -> read_stdin_acc(<<Acc/binary, Line/binary>>)
    end.

%% ═══ JSON Decoding ═════════════════════════════════════════════════════
%% Hand-rolled recursive descent parser for the flat Catseye JSON format.
%% All strings are returned as binaries (Erlang binaries = Gleam strings).

decode_json(Bin) when is_binary(Bin) ->
    decode_json(binary_to_list(Bin));
decode_json(Str) when is_list(Str) ->
    try
        {Value, _} = parse(skip_ws(Str)),
        case Value of
            Nodes when is_list(Nodes) ->
                {ok, [parse_node(N) || N <- Nodes]};
            _ ->
                {error, nil}
        end
    catch
        _:_ -> {error, nil}
    end.

%% ═══ Input Decoding (config-aware format) ═══════════════════════════════
%%
%% Parses: {"nodes": [...], "config": {"extra_taint_sources": [...], "extra_sanitizers": [...]}}
%%
%% Gleam types:
%%   Input(nodes: List(Node), config: EngineConfig)
%%   EngineConfig(extra_sources: List(String), extra_sanitizers: List(String))
%%
%% Erlang tuples:
%%   {input, List(Node), {engine_config, List(Binary), List(Binary)}}

decode_input(Bin) when is_binary(Bin) ->
    decode_input(binary_to_list(Bin));
decode_input(Str) when is_list(Str) ->
    try
        {Value, _} = parse(skip_ws(Str)),
        case Value of
            Map when is_map(Map) ->
                NodesRaw = maps:get(<<"nodes">>, Map, []),
                Nodes = [parse_node(N) || N <- NodesRaw],
                CfgRaw = maps:get(<<"config">>, Map, #{}),
                ExtraSources = bin_list(maps:get(<<"extra_taint_sources">>, CfgRaw, [])),
                ExtraSanitizers = bin_list(maps:get(<<"extra_sanitizers">>, CfgRaw, [])),
                {ok, {input, Nodes, {engine_config, ExtraSources, ExtraSanitizers}}};
            _ ->
                {error, nil}
        end
    catch
        _:_ -> {error, nil}
    end.

%% Convert a list of values to binary strings
bin_list(List) when is_list(List) ->
    [to_bin(L) || L <- List];
bin_list(_) -> [].

%% ═══ Parser core ═══════════════════════════════════════════════════════

%% ── Whitespace ─────────────────────────────────────────────────────────

skip_ws([$\s|T]) -> skip_ws(T);
skip_ws([$\t|T]) -> skip_ws(T);
skip_ws([$\n|T]) -> skip_ws(T);
skip_ws([$\r|T]) -> skip_ws(T);
skip_ws(T) -> T.

%% ── Value dispatch ────────────────────────────────────────────────────

parse([$[|T]) -> parse_array(skip_ws(T), []);
parse([${|T]) -> parse_object(skip_ws(T), []);
parse([$"|T]) -> parse_string(T, []);
parse([$t,$r,$u,$e|T]) -> {true, T};
parse([$f,$a,$l,$s,$e|T]) -> {false, T};
parse([$n,$u,$l,$l|T]) -> {null, T};
parse(S) when hd(S) =:= $-; (hd(S) >= $0 andalso hd(S) =< $9) ->
    parse_number(S, []).

%% ── Array ──────────────────────────────────────────────────────────────

parse_array([$]|T], Acc) -> {lists:reverse(Acc), T};
parse_array(T, Acc) ->
    {Val, T2} = parse(T),
    parse_array_comma(skip_ws(T2), [Val|Acc]).

parse_array_comma([$]|T], Acc) -> {lists:reverse(Acc), T};
parse_array_comma([$,|T], Acc) -> parse_array(skip_ws(T), Acc).

%% ── Object ─────────────────────────────────────────────────────────────

parse_object([$}|T], Acc) -> {maps:from_list(Acc), T};
parse_object([$"|T], Acc) ->
    {Key, T2} = parse_string(T, []),
    [$:|T3] = skip_ws(T2),
    {Val, T4} = parse(skip_ws(T3)),
    parse_object_comma(skip_ws(T4), [{Key, Val}|Acc]).

parse_object_comma([$}|T], Acc) -> {maps:from_list(Acc), T};
parse_object_comma([$,|T], Acc) -> parse_object(skip_ws(T), Acc).

%% ── String ─────────────────────────────────────────────────────────────

parse_string([$"|T], Acc) -> {list_to_binary(lists:reverse(Acc)), T};
parse_string([$\\,$n|T], Acc) -> parse_string(T, [$\n|Acc]);
parse_string([$\\,$t|T], Acc) -> parse_string(T, [$\t|Acc]);
parse_string([$\\,$r|T], Acc) -> parse_string(T, [$\r|Acc]);
parse_string([$\\,$"|T], Acc) -> parse_string(T, [$"|Acc]);
parse_string([$\\,$\\|T], Acc) -> parse_string(T, [$\\|Acc]);
parse_string([$\\,$/|T], Acc) -> parse_string(T, [$/|Acc]);
parse_string([C|T], Acc) -> parse_string(T, [C|Acc]).

%% ── Number ─────────────────────────────────────────────────────────────

parse_number([D|T], Acc) when D >= $0, D =< $9 -> parse_number(T, [D|Acc]);
parse_number([$.|T], Acc) -> parse_number(T, [$.|Acc]);
parse_number([$e|T], Acc) -> parse_number(T, [$e|Acc]);
parse_number([$E|T], Acc) -> parse_number(T, [$E|Acc]);
parse_number([$+|T], Acc) -> parse_number(T, [$+|Acc]);
parse_number([$-|T], Acc) -> parse_number(T, [$-|Acc]);
parse_number(T, Acc) ->
    S = lists:reverse(Acc),
    case lists:member($., S) orelse lists:member($e, S) orelse lists:member($E, S) of
        true -> {list_to_float(S), T};
        false -> {list_to_integer(S), T}
    end.

%% ═══ Node Parsing (map -> Gleam record tuple) ══════════════════════════

parse_node(Map) when is_map(Map) ->
    {node,
        node_type(maps:get(<<"type">>, Map, <<"call">>)),
        to_bin(maps:get(<<"name">>, Map, <<"">>)),
        [parse_arg(A) || A <- maps:get(<<"args">>, Map, [])],
        int_val(maps:get(<<"line">>, Map, 0)),
        bool_val(maps:get(<<"taint">>, Map, false)),
        to_bin(maps:get(<<"file">>, Map, <<"">>))}.

parse_arg(Map) when is_map(Map) ->
    {arg,
        arg_type(maps:get(<<"arg_type">>, Map, <<"unknown">>)),
        to_bin(maps:get(<<"value">>, Map, <<"">>))};
parse_arg(_) ->
    {arg, arg_unknown, <<>>}.

%% ── Safe accessors ─────────────────────────────────────────────────────

node_type(<<"call">>)    -> call;
node_type(<<"assign">>)  -> assign;
node_type(<<"def">>)     -> 'def';
node_type(<<"var">>)     -> var;
node_type(<<"literal">>) -> literal;
node_type(_)             -> call.

arg_type(<<"var">>)     -> arg_var;
arg_type(<<"literal">>) -> arg_literal;
arg_type(<<"call">>)    -> arg_call;
arg_type(_)             -> arg_unknown.

to_bin(B) when is_binary(B) -> B;
to_bin(I) when is_integer(I) -> integer_to_binary(I);
to_bin(L) when is_list(L) -> list_to_binary(L);
to_bin(_) -> <<>>.

int_val(I) when is_integer(I) -> I;
int_val(_) -> 0.

bool_val(B) when is_boolean(B) -> B;
bool_val(_) -> false.

%% ═══ JSON Encoding ═════════════════════════════════════════════════════

encode_findings(Findings) ->
    Parts = [finding_to_json(F) || F <- Findings],
    iolist_to_binary([$[, string:join(Parts, ","), $]]).

finding_to_json({finding, Rule, Severity, File, Line, Message, Flow}) ->
    FJ = flow_to_json(Flow),
    lists:flatten(io_lib:format(
        "{\"rule\":\"~s\",\"severity\":\"~s\",\"file\":\"~s\",\"line\":~p,\"message\":\"~s\",\"flow\":~s}",
        [esc(Rule), esc(Severity), esc(File), Line, esc(Message), FJ]
    ));
finding_to_json({finding, Rule, Severity, File, Line, Message}) ->
    lists:flatten(io_lib:format(
        "{\"rule\":\"~s\",\"severity\":\"~s\",\"file\":\"~s\",\"line\":~p,\"message\":\"~s\",\"flow\":[]}",
        [esc(Rule), esc(Severity), esc(File), Line, esc(Message)]
    ));
finding_to_json(_) -> "{}".

esc(Bin) when is_binary(Bin) -> esc(binary_to_list(Bin));
esc(List) when is_list(List) ->
    lists:flatten([escape_char(C) || C <- List]);
esc(_) -> <<>>.

escape_char($\\) -> "\\\\";
escape_char($")  -> "\\\"";
escape_char($\n) -> "\\n";
escape_char($\t) -> "\\t";
escape_char(C)   -> C.

flow_to_json(Steps) when is_list(Steps) ->
    Parts = [flow_step_to_json(S) || S <- Steps],
    iolist_to_binary([$[, string:join(Parts,","), $]]);
flow_to_json(_) -> "[]".

flow_step_to_json({flow_step, File, Line, Msg}) ->
    lists:flatten(io_lib:format(
        "{\"file\":\"~s\",\"line\":~p,\"message\":\"~s\"}",
        [esc(File), Line, esc(Msg)]
    ));
flow_step_to_json(_) -> "{}".
