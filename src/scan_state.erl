%%%-------------------------------------------------------------------
%%% @doc Scan State - Save and restore scan progress
%%% Enables resuming interrupted scans
%%% @end
%%%-------------------------------------------------------------------
-module(scan_state).

-export([
    save/3,
    load/1,
    delete/1,
    list_sessions/0,
    get_state_dir/0
]).

-define(STATE_DIR, ".massping_sessions").
-define(STATE_EXT, ".scanstate").

%%====================================================================
%% Types
%%====================================================================

-type scan_state() :: #{
    cidrs := [string()],
    ports := [inet:port_number()],
    options := map(),
    completed_chunks := [non_neg_integer()],
    total_chunks := non_neg_integer(),
    results := list(),
    started_at := integer(),
    last_updated := integer()
}.

-export_type([scan_state/0]).

%%====================================================================
%% API
%%====================================================================

%% @doc Save scan state to file
-spec save(string(), scan_state(), string()) -> ok | {error, term()}.
save(SessionId, State, StateDir) ->
    ensure_state_dir(StateDir),
    Filename = filename:join(StateDir, SessionId ++ ?STATE_EXT),
    StateWithTime = State#{last_updated => erlang:system_time(second)},
    Data = term_to_binary(StateWithTime, [compressed]),
    file:write_file(Filename, Data).

%% @doc Load scan state from file
-spec load(string()) -> {ok, scan_state()} | {error, term()}.
load(SessionId) ->
    StateDir = get_state_dir(),
    Filename = filename:join(StateDir, SessionId ++ ?STATE_EXT),
    case file:read_file(Filename) of
        {ok, Data} ->
            try
                {ok, binary_to_term(Data)}
            catch
                _:_ -> {error, corrupt_state}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Delete scan state
-spec delete(string()) -> ok | {error, term()}.
delete(SessionId) ->
    StateDir = get_state_dir(),
    Filename = filename:join(StateDir, SessionId ++ ?STATE_EXT),
    file:delete(Filename).

%% @doc List all saved sessions
-spec list_sessions() -> [{string(), integer(), float()}].
list_sessions() ->
    StateDir = get_state_dir(),
    case file:list_dir(StateDir) of
        {ok, Files} ->
            lists:filtermap(fun(F) ->
                case filename:extension(F) of
                    ?STATE_EXT ->
                        SessionId = filename:basename(F, ?STATE_EXT),
                        case load(SessionId) of
                            {ok, State} ->
                                Completed = length(maps:get(completed_chunks, State, [])),
                                Total = maps:get(total_chunks, State, 1),
                                Progress = (Completed / max(Total, 1)) * 100,
                                LastUpdated = maps:get(last_updated, State, 0),
                                {true, {SessionId, LastUpdated, Progress}};
                            _ ->
                                false
                        end;
                    _ ->
                        false
                end
            end, Files);
        {error, _} ->
            []
    end.

%% @doc Get state directory
-spec get_state_dir() -> string().
get_state_dir() ->
    case os:getenv("HOME") of
        false -> ?STATE_DIR;
        Home -> filename:join(Home, ?STATE_DIR)
    end.

%%====================================================================
%% Internal functions
%%====================================================================

ensure_state_dir(Dir) ->
    case filelib:is_dir(Dir) of
        true -> ok;
        false -> filelib:ensure_dir(filename:join(Dir, "dummy"))
    end.
