%%%-------------------------------------------------------------------
%%% @doc Adaptive rate controller based on packet loss detection
%%% 
%%% Implements AIMD (Additive Increase Multiplicative Decrease) similar
%%% to TCP congestion control, but for scan rate.
%%% 
%%% When filtered results increase → decrease rate (congestion)
%%% When filtered results decrease → increase rate
%%% @end
%%%-------------------------------------------------------------------
-module(adaptive_rate).
-behaviour(gen_server).

-export([
    start_link/1,
    report_result/2,
    get_current_rate/1,
    get_stats/1,
    stop/1
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-record(state, {
    %% Rate parameters
    current_rate :: pos_integer(),      % Current packets/sec
    min_rate :: pos_integer(),          % Minimum rate
    max_rate :: pos_integer(),          % Maximum rate
    initial_rate :: pos_integer(),      % Starting rate
    
    %% AIMD parameters
    additive_increase :: pos_integer(), % Increase per window
    multiplicative_decrease :: float(), % Decrease factor (0.5 = halve)
    
    %% Window tracking
    window_size :: pos_integer(),       % Results per window
    window_results :: [atom()],         % Results in current window
    
    %% Statistics
    total_sent :: non_neg_integer(),
    total_open :: non_neg_integer(),
    total_closed :: non_neg_integer(),
    total_filtered :: non_neg_integer(),
    
    %% Loss tracking
    loss_history :: [float()],          % Last N loss ratios
    avg_loss :: float()
}).

-define(DEFAULT_MIN_RATE, 100).
-define(DEFAULT_MAX_RATE, 100000).
-define(DEFAULT_WINDOW_SIZE, 1000).
-define(DEFAULT_ADDITIVE_INCREASE, 500).
-define(DEFAULT_MULTIPLICATIVE_DECREASE, 0.7).
-define(LOSS_HISTORY_SIZE, 10).
-define(LOSS_THRESHOLD, 0.3).  % 30% filtered = congestion

%%====================================================================
%% API
%%====================================================================

-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link(?MODULE, Opts, []).

%% @doc Report a scan result for rate adaptation
-spec report_result(pid(), atom()) -> ok.
report_result(Pid, Result) when Result =:= open; Result =:= closed; Result =:= filtered ->
    gen_server:cast(Pid, {result, Result}).

%% @doc Get current rate
-spec get_current_rate(pid()) -> pos_integer().
get_current_rate(Pid) ->
    gen_server:call(Pid, get_rate).

%% @doc Get statistics
-spec get_stats(pid()) -> map().
get_stats(Pid) ->
    gen_server:call(Pid, get_stats).

-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init(Opts) ->
    InitialRate = maps:get(initial_rate, Opts, 5000),
    MinRate = maps:get(min_rate, Opts, ?DEFAULT_MIN_RATE),
    MaxRate = maps:get(max_rate, Opts, ?DEFAULT_MAX_RATE),
    
    {ok, #state{
        current_rate = InitialRate,
        min_rate = MinRate,
        max_rate = MaxRate,
        initial_rate = InitialRate,
        additive_increase = maps:get(additive_increase, Opts, ?DEFAULT_ADDITIVE_INCREASE),
        multiplicative_decrease = maps:get(multiplicative_decrease, Opts, ?DEFAULT_MULTIPLICATIVE_DECREASE),
        window_size = maps:get(window_size, Opts, ?DEFAULT_WINDOW_SIZE),
        window_results = [],
        total_sent = 0,
        total_open = 0,
        total_closed = 0,
        total_filtered = 0,
        loss_history = [],
        avg_loss = 0.0
    }}.

handle_call(get_rate, _From, State) ->
    {reply, State#state.current_rate, State};

handle_call(get_stats, _From, State) ->
    Stats = #{
        current_rate => State#state.current_rate,
        total_sent => State#state.total_sent,
        total_open => State#state.total_open,
        total_closed => State#state.total_closed,
        total_filtered => State#state.total_filtered,
        avg_loss => State#state.avg_loss,
        loss_history => State#state.loss_history
    },
    {reply, Stats, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({result, Result}, State) ->
    %% Update counters
    NewState = update_counters(Result, State),
    
    %% Add to window
    WindowResults = [Result | NewState#state.window_results],
    
    %% Check if window is complete
    case length(WindowResults) >= NewState#state.window_size of
        true ->
            %% Analyze window and adjust rate
            FinalState = analyze_and_adjust(WindowResults, NewState),
            {noreply, FinalState#state{window_results = []}};
        false ->
            {noreply, NewState#state{window_results = WindowResults}}
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================

update_counters(open, State) ->
    State#state{
        total_sent = State#state.total_sent + 1,
        total_open = State#state.total_open + 1
    };
update_counters(closed, State) ->
    State#state{
        total_sent = State#state.total_sent + 1,
        total_closed = State#state.total_closed + 1
    };
update_counters(filtered, State) ->
    State#state{
        total_sent = State#state.total_sent + 1,
        total_filtered = State#state.total_filtered + 1
    }.

analyze_and_adjust(WindowResults, State) ->
    %% Calculate loss ratio in this window
    FilteredCount = length([R || R <- WindowResults, R =:= filtered]),
    LossRatio = FilteredCount / length(WindowResults),
    
    %% Update loss history
    LossHistory = lists:sublist([LossRatio | State#state.loss_history], ?LOSS_HISTORY_SIZE),
    AvgLoss = lists:sum(LossHistory) / length(LossHistory),
    
    %% AIMD logic
    NewRate = case LossRatio > ?LOSS_THRESHOLD of
        true ->
            %% Multiplicative decrease - congestion detected
            DecreasedRate = round(State#state.current_rate * State#state.multiplicative_decrease),
            max(State#state.min_rate, DecreasedRate);
        false ->
            %% Additive increase - no congestion
            IncreasedRate = State#state.current_rate + State#state.additive_increase,
            min(State#state.max_rate, IncreasedRate)
    end,
    
    State#state{
        current_rate = NewRate,
        loss_history = LossHistory,
        avg_loss = AvgLoss
    }.

%%====================================================================
%% Tests
%%====================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

basic_test() ->
    {ok, Pid} = start_link(#{initial_rate => 1000}),
    ?assertEqual(1000, get_current_rate(Pid)),
    stop(Pid).

-endif.
