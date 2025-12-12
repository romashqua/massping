%%%-------------------------------------------------------------------
%%% @doc MassPing application callback module
%%% @end
%%%-------------------------------------------------------------------
-module(massping_app).
-behaviour(application).

-export([start/2, stop/1]).

%%====================================================================
%% API
%%====================================================================

start(_StartType, _StartArgs) ->
    io:format("Starting MassPing v1.0.0~n"),
    case massping_sup:start_link() of
        {ok, Pid} ->
            io:format("MassPing started successfully~n"),
            {ok, Pid};
        Error ->
            io:format("Failed to start MassPing: ~p~n", [Error]),
            Error
    end.

stop(_State) ->
    io:format("Stopping MassPing~n"),
    ok.

%%====================================================================
%% Internal functions
%%====================================================================
