%%%-------------------------------------------------------------------
%%% @doc SYN Scanner NIF Interface
%%% High-performance SYN port scanning using raw sockets.
%%% Requires root privileges (sudo) to function.
%%%
%%% SYN scan benefits:
%%% - 3x faster than TCP connect (1 packet vs 3 packets)
%%% - Half-open scan (less detectable)
%%% - Lower resource usage (no socket state)
%%%
%%% Usage:
%%%   syn_scanner:is_available() -> true | false
%%%   syn_scanner:scan({192,168,1,1}, 80, 1000) -> {open, 80} | {closed, 80} | {filtered, 80}
%%%   syn_scanner:scan_batch([{{192,168,1,1}, 80}, ...], 1000) -> [{IP, Result, Port}, ...]
%%% @end
%%%-------------------------------------------------------------------
-module(syn_scanner).

-export([
    is_available/0,
    is_root/0,
    init/0,
    scan/3,
    scan_batch/2,
    cleanup/0
]).

%% NIF functions (loaded from C)
-nifs([init/0, is_root/0, syn_scan/3, syn_scan_batch/2, cleanup/0]).

-on_load(load_nif/0).

%%====================================================================
%% NIF Loading
%%====================================================================

load_nif() ->
    %% Try multiple locations for the NIF
    Paths = [
        %% Standard priv_dir (when running as release)
        case code:priv_dir(massping) of
            {error, _} -> undefined;
            Dir -> filename:join(Dir, "syn_scanner")
        end,
        %% Development path
        filename:join([code:lib_dir(massping), "priv", "syn_scanner"]),
        %% Escript: NIF in same directory as escript
        case escript:script_name() of
            "" -> undefined;
            Script ->
                ScriptDir = filename:dirname(Script),
                filename:join([ScriptDir, "..", "priv", "syn_scanner"])
        end,
        %% Current directory
        filename:join(["priv", "syn_scanner"]),
        %% Build directory
        filename:join(["_build", "default", "lib", "massping", "priv", "syn_scanner"])
    ],
    
    ValidPaths = [P || P <- Paths, P =/= undefined],
    load_nif_from_paths(ValidPaths).

load_nif_from_paths([]) ->
    %% NIF not found - this is OK, we fall back to TCP connect
    ok;
load_nif_from_paths([Path | Rest]) ->
    case erlang:load_nif(Path, 0) of
        ok -> ok;
        {error, {reload, _}} -> ok;  %% Already loaded
        {error, _} -> load_nif_from_paths(Rest)
    end.

%%====================================================================
%% API
%%====================================================================

%% @doc Check if SYN scanning is available
%% Returns true only if:
%% 1. NIF is loaded
%% 2. Running as root
%% 3. Raw sockets can be created
%% Works on both Linux (raw sockets) and macOS (libpcap)
-spec is_available() -> boolean().
is_available() ->
    try
        case is_root() of
            true ->
                case init() of
                    {ok, _LocalIP} -> true;
                    _ -> false
                end;
            false ->
                false
        end
    catch
        error:undef -> false;  %% NIF not loaded
        _:_ -> false
    end.

%% @doc Check if running as root
-spec is_root() -> boolean().
is_root() ->
    erlang:nif_error(nif_not_loaded).

%% @doc Initialize raw sockets
%% Must be called before scanning if using SYN mode
-spec init() -> {ok, string()} | {error, term()}.
init() ->
    erlang:nif_error(nif_not_loaded).

%% @doc Single target SYN scan
-spec scan(inet:ip4_address(), inet:port_number(), pos_integer()) ->
    {open | closed | filtered, inet:port_number()} | {error, term()}.
scan(IP, Port, TimeoutMs) ->
    try
        syn_scan(IP, Port, TimeoutMs)
    catch
        error:undef ->
            %% NIF not loaded, fall back to TCP connect
            fallback_scan(IP, Port, TimeoutMs)
    end.

%% @doc Batch SYN scan - much faster for multiple targets
%% Sends all SYN packets first, then collects responses
-spec scan_batch([{inet:ip4_address(), inet:port_number()}], pos_integer()) ->
    {ok, [{inet:ip4_address(), {open | closed | filtered, inet:port_number()}, inet:port_number()}]} |
    {error, term()}.
scan_batch(Targets, TimeoutMs) ->
    try
        syn_scan_batch(Targets, TimeoutMs)
    catch
        error:undef ->
            %% NIF not loaded, fall back to TCP connect (parallel)
            {ok, fallback_scan_batch(Targets, TimeoutMs)}
    end.

%% @doc Cleanup raw sockets
-spec cleanup() -> ok.
cleanup() ->
    try
        cleanup_nif()
    catch
        error:undef -> ok
    end,
    ok.

%%====================================================================
%% Internal NIF stubs (replaced by C code when loaded)
%%====================================================================

syn_scan(_IP, _Port, _TimeoutMs) ->
    erlang:nif_error(nif_not_loaded).

syn_scan_batch(_Targets, _TimeoutMs) ->
    erlang:nif_error(nif_not_loaded).

cleanup_nif() ->
    erlang:nif_error(nif_not_loaded).

%%====================================================================
%% Fallback implementation (TCP connect)
%%====================================================================

fallback_scan(IP, Port, TimeoutMs) ->
    case gen_tcp:connect(IP, Port, [binary, {active, false}], TimeoutMs) of
        {ok, Socket} ->
            gen_tcp:close(Socket),
            {open, Port};
        {error, econnrefused} ->
            {closed, Port};
        {error, _} ->
            {filtered, Port}
    end.

fallback_scan_batch(Targets, TimeoutMs) ->
    %% Parallel TCP connect fallback
    Parent = self(),
    Refs = lists:map(fun({IP, Port}) ->
        Ref = make_ref(),
        spawn(fun() ->
            Result = fallback_scan(IP, Port, TimeoutMs),
            Parent ! {Ref, IP, Result, Port}
        end),
        Ref
    end, Targets),
    
    %% Collect results
    [receive {Ref, IP, Result, Port} -> {IP, Result, Port} end || Ref <- Refs].

%%====================================================================
%% Tests
%%====================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

is_available_test() ->
    %% Should not crash
    _ = is_available(),
    ok.

fallback_scan_test() ->
    %% Test fallback to localhost
    Result = fallback_scan({127,0,0,1}, 12345, 100),
    ?assertMatch({_, 12345}, Result).

-endif.
