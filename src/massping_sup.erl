%%%-------------------------------------------------------------------
%%% @doc Top-level supervisor for MassPing application
%%% @end
%%%-------------------------------------------------------------------
-module(massping_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 10,
        period => 10
    },
    
    ChildSpecs = [
        #{
            id => scanner_sup,
            start => {scanner_sup, start_link, []},
            restart => permanent,
            shutdown => 5000,
            type => supervisor,
            modules => [scanner_sup]
        },
        #{
            id => massping_core,
            start => {massping_core, start_link, []},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [massping_core]
        },
        #{
            id => massping_scan_manager,
            start => {massping_scan_manager, start_link, []},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [massping_scan_manager]
        }
    ],
    
    {ok, {SupFlags, ChildSpecs}}.

%%====================================================================
%% Internal functions
%%====================================================================
