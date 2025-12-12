%%%-------------------------------------------------------------------
%%% @doc Scanner supervisor - manages pool of scanner workers
%%% Implements dynamic worker creation and load balancing
%%% @end
%%%-------------------------------------------------------------------
-module(scanner_sup).
-behaviour(supervisor).

%% API
-export([
    start_link/0,
    start_worker/5,
    stop_worker/1,
    get_worker_count/0
]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% @doc Start a new scanner worker
-spec start_worker(tuple(), pos_integer(), pos_integer(), pid(), pid()) ->
    {ok, pid()} | {error, term()}.
start_worker(IP, Port, Timeout, Parent, RateLimiter) ->
    supervisor:start_child(?SERVER, [IP, Port, Timeout, Parent, RateLimiter]).

%% @doc Stop a scanner worker
-spec stop_worker(pid()) -> ok.
stop_worker(Pid) ->
    supervisor:terminate_child(?SERVER, Pid).

%% @doc Get current number of active workers
-spec get_worker_count() -> non_neg_integer().
get_worker_count() ->
    proplists:get_value(active, supervisor:count_children(?SERVER), 0).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

init([]) ->
    SupFlags = #{
        strategy => simple_one_for_one,
        intensity => 1000,
        period => 1
    },
    
    ChildSpecs = [
        #{
            id => scanner_worker,
            start => {scanner_worker, start_link, []},
            restart => temporary,
            shutdown => 5000,
            type => worker,
            modules => [scanner_worker]
        }
    ],
    
    {ok, {SupFlags, ChildSpecs}}.

%%====================================================================
%% Internal functions
%%====================================================================
