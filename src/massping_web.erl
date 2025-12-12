%%%-------------------------------------------------------------------
%%% @doc MassPing Web Server
%%% Starts Cowboy HTTP server for REST API and Web UI
%%% @end
%%%-------------------------------------------------------------------
-module(massping_web).

-export([
    start/0,
    start/1,
    stop/0
]).

-define(DEFAULT_PORT, 8080).

%%====================================================================
%% API
%%====================================================================

%% @doc Start web server on default port (8080)
start() ->
    start(#{port => ?DEFAULT_PORT}).

%% @doc Start web server with options
%% Options: #{port => 8080, ip => {0,0,0,0}}
start(Options) ->
    Port = maps:get(port, Options, ?DEFAULT_PORT),
    IP = maps:get(ip, Options, {0, 0, 0, 0}),
    
    %% Setup metrics
    massping_metrics:setup(),
    
    %% Start scanner_sup if not running (needed for worker pool)
    case whereis(scanner_sup) of
        undefined ->
            {ok, _} = scanner_sup:start_link();
        _ ->
            ok
    end,
    
    %% Start massping_core if not running
    case whereis(massping_core) of
        undefined ->
            {ok, _} = massping_core:start_link();
        _ ->
            ok
    end,
    
    %% Start scan manager if not running
    case whereis(massping_scan_manager) of
        undefined ->
            {ok, _} = massping_scan_manager:start_link();
        _ ->
            ok
    end,
    
    %% Routes
    Dispatch = cowboy_router:compile([
        {'_', [
            %% Web UI
            {"/", massping_web_handler, []},
            {"/dashboard", massping_web_handler, []},
            {"/metrics", massping_web_handler, []},
            {"/health", massping_web_handler, []},
            
            %% REST API
            {"/api/status", massping_api_handler, []},
            {"/api/scans", massping_api_handler, []},
            {"/api/scans/:scan_id", massping_api_handler, []},
            {"/api/scans/:scan_id/results", massping_api_handler, []},
            {"/api/sessions", massping_api_handler, []},
            {"/api/sessions/:session_id/resume", massping_api_handler, []},
            {"/api/cluster", massping_api_handler, []},
            {"/api/cluster/nodes", massping_api_handler, []}
        ]}
    ]),
    
    %% Start Cowboy
    case cowboy:start_clear(massping_http_listener,
        [{port, Port}, {ip, IP}],
        #{env => #{dispatch => Dispatch}}
    ) of
        {ok, _} ->
            io:format("~n"),
            io:format("╔════════════════════════════════════════════════════════════╗~n"),
            io:format("║           MassPing Web Dashboard Started                    ║~n"),
            io:format("╠════════════════════════════════════════════════════════════╣~n"),
            io:format("║  Dashboard:  http://localhost:~B/                          ~n", [Port]),
            io:format("║  API:        http://localhost:~B/api/                       ~n", [Port]),
            io:format("║  Metrics:    http://localhost:~B/metrics                    ~n", [Port]),
            io:format("║  Health:     http://localhost:~B/health                     ~n", [Port]),
            io:format("╚════════════════════════════════════════════════════════════╝~n"),
            io:format("~n"),
            {ok, Port};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Stop web server
stop() ->
    cowboy:stop_listener(massping_http_listener).
