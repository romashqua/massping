%%%-------------------------------------------------------------------
%%% @doc Scanner worker - non-blocking TCP port scanner
%%% Each worker is a lightweight process that scans one port
%%% @end
%%%-------------------------------------------------------------------
-module(scanner_worker).
-behaviour(gen_server).

%% API
-export([
    start_link/5,
    stop/1,
    get_result/1
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-record(state, {
    ip :: tuple(),
    port :: pos_integer(),
    timeout :: pos_integer(),
    parent :: pid(),
    socket :: port() | undefined,
    start_time :: integer(),
    result :: term()
}).

-type scan_result() :: {open, pos_integer()} | 
                       {closed, pos_integer()} | 
                       {filtered, pos_integer()} |
                       {error, term()}.

%%====================================================================
%% API
%%====================================================================

%% @doc Start scanner worker for single IP:Port combination
-spec start_link(tuple(), pos_integer(), pos_integer(), pid(), pid()) -> 
    {ok, pid()} | {error, term()}.
start_link(IP, Port, Timeout, Parent, RateLimiter) ->
    gen_server:start_link(?MODULE, [IP, Port, Timeout, Parent, RateLimiter], []).

%% @doc Stop scanner worker
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

%% @doc Get scan result (blocking)
-spec get_result(pid()) -> scan_result().
get_result(Pid) ->
    gen_server:call(Pid, get_result, infinity).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([IP, Port, Timeout, Parent, RateLimiter]) ->
    %% Acquire permission from rate limiter
    ok = rate_limiter:acquire(RateLimiter),
    
    %% Start scanning immediately after acquiring permission
    self() ! start_scan,
    
    {ok, #state{
        ip = IP,
        port = Port,
        timeout = Timeout,
        parent = Parent,
        start_time = erlang:monotonic_time(millisecond),
        result = undefined
    }}.

handle_call(get_result, _From, State) ->
    case State#state.result of
        undefined ->
            {reply, {error, not_ready}, State};
        Result ->
            {reply, Result, State}
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(start_scan, State) ->
    %% Start non-blocking connect
    case connect_nonblocking(State#state.ip, State#state.port, State#state.timeout) of
        {ok, Socket} ->
            NewState = State#state{socket = Socket},
            {noreply, NewState};
        {error, in_progress, Socket} ->
            %% Connection in progress, wait for result
            erlang:send_after(State#state.timeout, self(), scan_timeout),
            NewState = State#state{socket = Socket},
            {noreply, NewState};
        {error, Reason} ->
            Result = classify_error(Reason, State#state.port),
            notify_parent(State#state.parent, State#state.ip, Result),
            {stop, normal, State#state{result = Result}}
    end;

handle_info({tcp, Socket, _Data}, State) when Socket =:= State#state.socket ->
    %% Connection successful - port is open
    gen_tcp:close(Socket),
    Result = {open, State#state.port},
    notify_parent(State#state.parent, State#state.ip, Result),
    {stop, normal, State#state{result = Result}};

handle_info({tcp_closed, Socket}, State) when Socket =:= State#state.socket ->
    %% Connection closed after establishing - still means port was open
    Result = {open, State#state.port},
    notify_parent(State#state.parent, State#state.ip, Result),
    {stop, normal, State#state{result = Result}};

handle_info({tcp_error, Socket, Reason}, State) when Socket =:= State#state.socket ->
    Result = classify_error(Reason, State#state.port),
    notify_parent(State#state.parent, State#state.ip, Result),
    {stop, normal, State#state{result = Result}};

handle_info(scan_timeout, State) ->
    %% Timeout - classify based on socket state
    Result = case State#state.socket of
        undefined ->
            {filtered, State#state.port};
        Socket ->
            %% Try to check connection status
            case inet:peername(Socket) of
                {ok, _} ->
                    gen_tcp:close(Socket),
                    {open, State#state.port};
                {error, _} ->
                    gen_tcp:close(Socket),
                    {filtered, State#state.port}
            end
    end,
    notify_parent(State#state.parent, State#state.ip, Result),
    {stop, normal, State#state{result = Result}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    case State#state.socket of
        undefined -> ok;
        Socket -> 
            catch gen_tcp:close(Socket)
    end,
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal functions
%%====================================================================

%% Non-blocking TCP connect
-spec connect_nonblocking(tuple(), pos_integer(), pos_integer()) ->
    {ok, port()} | {error, in_progress, port()} | {error, term()}.
connect_nonblocking(IP, Port, Timeout) ->
    Opts = [
        binary,
        {active, true},
        {packet, raw},
        {send_timeout, Timeout},
        {send_timeout_close, true}
    ],
    
    case gen_tcp:connect(IP, Port, Opts, Timeout) of
        {ok, Socket} ->
            {ok, Socket};
        {error, timeout} ->
            {error, timeout};
        {error, econnrefused} ->
            {error, econnrefused};
        {error, ehostunreach} ->
            {error, ehostunreach};
        {error, enetunreach} ->
            {error, enetunreach};
        {error, etimedout} ->
            {error, etimedout};
        {error, Reason} ->
            {error, Reason}
    end.

%% Classify error into scan result
-spec classify_error(term(), pos_integer()) -> scan_result().
classify_error(econnrefused, Port) ->
    {closed, Port};
classify_error(timeout, Port) ->
    {filtered, Port};
classify_error(etimedout, Port) ->
    {filtered, Port};
classify_error(ehostunreach, Port) ->
    {filtered, Port};
classify_error(enetunreach, Port) ->
    {filtered, Port};
classify_error(Reason, _Port) ->
    {error, Reason}.

%% Notify parent process of result
-spec notify_parent(pid(), tuple(), scan_result()) -> ok.
notify_parent(Parent, IP, Result) ->
    Parent ! {scan_result, IP, Result},
    ok.

%%====================================================================
%% Tests
%%====================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

%% Note: These tests require a rate limiter to be running
%% They are integration tests rather than unit tests

-endif.
