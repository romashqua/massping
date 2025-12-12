%%%-------------------------------------------------------------------
%%% @doc Rate limiter gen_server for precise control of scan rate
%%% Supports uniform distribution and burst modes
%%% @end
%%%-------------------------------------------------------------------
-module(rate_limiter).
-behaviour(gen_server).

%% API
-export([
    start_link/1,
    start_link/2,
    stop/1,
    acquire/1,
    acquire/2,
    set_rate/2,
    get_rate/1,
    get_stats/1,
    reset/1
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
    rate :: pos_integer(),          % requests per second
    tokens :: float(),              % current tokens available
    max_tokens :: float(),          % max tokens (burst capacity)
    last_update :: integer(),       % last token update time (microseconds)
    strategy :: uniform | burst,    % distribution strategy
    waiting :: queue:queue(),       % queue of waiting processes
    stats :: map()                  % statistics
}).

-define(MILLION, 1000000).

%%====================================================================
%% API
%%====================================================================

%% @doc Start rate limiter with default uniform strategy
-spec start_link(pos_integer()) -> {ok, pid()} | {error, term()}.
start_link(Rate) ->
    start_link(Rate, uniform).

%% @doc Start rate limiter with specified strategy
-spec start_link(pos_integer(), uniform | burst) -> {ok, pid()} | {error, term()}.
start_link(Rate, Strategy) ->
    gen_server:start_link(?MODULE, [Rate, Strategy], []).

%% @doc Stop rate limiter
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

%% @doc Acquire permission to proceed (blocking)
-spec acquire(pid()) -> ok | {error, term()}.
acquire(Pid) ->
    acquire(Pid, infinity).

%% @doc Acquire permission with timeout
-spec acquire(pid(), timeout()) -> ok | {error, term()}.
acquire(Pid, Timeout) ->
    gen_server:call(Pid, {acquire, self()}, Timeout).

%% @doc Change rate limit dynamically
-spec set_rate(pid(), pos_integer()) -> ok.
set_rate(Pid, NewRate) ->
    gen_server:cast(Pid, {set_rate, NewRate}).

%% @doc Get current rate
-spec get_rate(pid()) -> pos_integer().
get_rate(Pid) ->
    gen_server:call(Pid, get_rate).

%% @doc Get statistics
-spec get_stats(pid()) -> map().
get_stats(Pid) ->
    gen_server:call(Pid, get_stats).

%% @doc Reset statistics
-spec reset(pid()) -> ok.
reset(Pid) ->
    gen_server:cast(Pid, reset).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([Rate, Strategy]) ->
    MaxTokens = case Strategy of
        uniform -> Rate;  % 1 second worth of tokens
        burst -> Rate * 5  % 5 seconds worth for burst
    end,
    
    State = #state{
        rate = Rate,
        tokens = MaxTokens,
        max_tokens = MaxTokens,
        last_update = erlang:monotonic_time(microsecond),
        strategy = Strategy,
        waiting = queue:new(),
        stats = #{
            total_requests => 0,
            granted => 0,
            denied => 0,
            avg_wait_time => 0
        }
    },
    
    %% Schedule token refill
    schedule_refill(),
    
    {ok, State}.

handle_call({acquire, Pid}, From, State) ->
    NewState = update_tokens(State),
    
    case NewState#state.tokens >= 1.0 of
        true ->
            %% Grant immediately
            FinalState = consume_token(NewState),
            StatsState = update_stats(FinalState, granted),
            {reply, ok, StatsState};
        false ->
            %% Add to waiting queue
            Waiting = queue:in({From, Pid, erlang:monotonic_time(microsecond)}, 
                              NewState#state.waiting),
            {noreply, NewState#state{waiting = Waiting}}
    end;

handle_call(get_rate, _From, State) ->
    {reply, State#state.rate, State};

handle_call(get_stats, _From, State) ->
    {reply, State#state.stats, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({set_rate, NewRate}, State) ->
    MaxTokens = case State#state.strategy of
        uniform -> NewRate;
        burst -> NewRate * 5
    end,
    
    NewState = State#state{
        rate = NewRate,
        max_tokens = MaxTokens,
        tokens = min(State#state.tokens, MaxTokens)
    },
    
    {noreply, NewState};

handle_cast(reset, State) ->
    NewState = State#state{
        stats = #{
            total_requests => 0,
            granted => 0,
            denied => 0,
            avg_wait_time => 0
        }
    },
    {noreply, NewState};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(refill_tokens, State) ->
    NewState = update_tokens(State),
    ProcessedState = process_waiting(NewState),
    schedule_refill(),
    {noreply, ProcessedState};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal functions
%%====================================================================

%% Update available tokens based on time elapsed
-spec update_tokens(#state{}) -> #state{}.
update_tokens(State) ->
    Now = erlang:monotonic_time(microsecond),
    TimeDelta = Now - State#state.last_update,
    
    %% Calculate tokens to add (rate per second converted to microseconds)
    TokensToAdd = (State#state.rate * TimeDelta) / ?MILLION,
    
    NewTokens = min(State#state.tokens + TokensToAdd, State#state.max_tokens),
    
    State#state{
        tokens = NewTokens,
        last_update = Now
    }.

%% Consume one token
-spec consume_token(#state{}) -> #state{}.
consume_token(State) ->
    State#state{tokens = State#state.tokens - 1.0}.

%% Process waiting queue
-spec process_waiting(#state{}) -> #state{}.
process_waiting(State) ->
    case queue:is_empty(State#state.waiting) of
        true ->
            State;
        false ->
            process_waiting_loop(State)
    end.

process_waiting_loop(State) when State#state.tokens < 1.0 ->
    State;
process_waiting_loop(State) ->
    case queue:out(State#state.waiting) of
        {empty, _} ->
            State;
        {{value, {From, _Pid, StartTime}}, NewQueue} ->
            case State#state.tokens >= 1.0 of
                true ->
                    gen_server:reply(From, ok),
                    WaitTime = erlang:monotonic_time(microsecond) - StartTime,
                    NewState = consume_token(State),
                    StatsState = update_stats(NewState, granted, WaitTime),
                    process_waiting_loop(StatsState#state{waiting = NewQueue});
                false ->
                    State
            end
    end.

%% Schedule next token refill
-spec schedule_refill() -> reference().
schedule_refill() ->
    %% Refill every 10ms for smooth rate limiting
    erlang:send_after(10, self(), refill_tokens).

%% Update statistics
-spec update_stats(#state{}, granted | denied) -> #state{}.
update_stats(State, Type) ->
    update_stats(State, Type, 0).

-spec update_stats(#state{}, granted | denied, non_neg_integer()) -> #state{}.
update_stats(State, Type, WaitTime) ->
    Stats = State#state.stats,
    Total = maps:get(total_requests, Stats) + 1,
    TypeCount = maps:get(Type, Stats) + 1,
    
    AvgWait = case Type of
        granted ->
            OldAvg = maps:get(avg_wait_time, Stats),
            OldCount = maps:get(granted, Stats),
            (OldAvg * OldCount + WaitTime) / TypeCount;
        denied ->
            maps:get(avg_wait_time, Stats)
    end,
    
    NewStats = Stats#{
        total_requests => Total,
        Type => TypeCount,
        avg_wait_time => AvgWait
    },
    
    State#state{stats = NewStats}.

%%====================================================================
%% Tests
%%====================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

rate_limiter_basic_test() ->
    {ok, Pid} = start_link(100),
    
    %% Should acquire immediately with fresh limiter
    ?assertEqual(ok, acquire(Pid)),
    
    Rate = get_rate(Pid),
    ?assertEqual(100, Rate),
    
    stop(Pid).

rate_limiter_stats_test() ->
    {ok, Pid} = start_link(1000),
    
    %% Make some requests
    [acquire(Pid) || _ <- lists:seq(1, 10)],
    
    Stats = get_stats(Pid),
    ?assert(maps:get(granted, Stats) > 0),
    ?assert(maps:get(total_requests, Stats) >= 10),
    
    stop(Pid).

rate_limiter_change_rate_test() ->
    {ok, Pid} = start_link(100),
    
    ok = set_rate(Pid, 200),
    timer:sleep(20),
    
    ?assertEqual(200, get_rate(Pid)),
    
    stop(Pid).

-endif.
