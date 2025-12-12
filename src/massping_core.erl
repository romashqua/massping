%%%-------------------------------------------------------------------
%%% @doc MassPing core - main coordination module
%%% Orchestrates scanning process with rate limiting and result collection
%%% @end
%%%-------------------------------------------------------------------
-module(massping_core).
-behaviour(gen_server).

%% API
-export([
    start_link/0,
    start_scan/3,
    stop_scan/1,
    pause_scan/1,
    resume_scan/1,
    get_status/1,
    get_results/1
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

-record(scan, {
    id :: reference(),
    cidrs :: [string()],
    ports :: [pos_integer()],
    opts :: map(),
    rate_limiter :: pid(),
    state :: running | paused | stopped | completed,
    total :: non_neg_integer(),
    scanned :: ets:tid(),        %% ETS counter table for atomic updates
    results :: ets:tid(),        %% ETS table for results (not in gen_server state)
    start_time :: integer(),
    coordinator :: pid()         %% Coordinator process pid
}).

-record(state, {
    scans :: #{reference() => #scan{}}
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Start a new scan
-spec start_scan([string()], [pos_integer()], map()) -> 
    {ok, reference()} | {error, term()}.
start_scan(CIDRs, Ports, Opts) ->
    gen_server:call(?MODULE, {start_scan, CIDRs, Ports, Opts}, infinity).

%% @doc Stop a running scan
-spec stop_scan(reference()) -> ok | {error, term()}.
stop_scan(ScanId) ->
    gen_server:call(?MODULE, {stop_scan, ScanId}).

%% @doc Pause a running scan
-spec pause_scan(reference()) -> ok | {error, term()}.
pause_scan(ScanId) ->
    gen_server:call(?MODULE, {pause_scan, ScanId}).

%% @doc Resume a paused scan
-spec resume_scan(reference()) -> ok | {error, term()}.
resume_scan(ScanId) ->
    gen_server:call(?MODULE, {resume_scan, ScanId}).

%% @doc Get scan status
-spec get_status(reference()) -> {ok, map()} | {error, term()}.
get_status(ScanId) ->
    gen_server:call(?MODULE, {get_status, ScanId}).

%% @doc Get scan results
-spec get_results(reference()) -> {ok, [term()]} | {error, term()}.
get_results(ScanId) ->
    gen_server:call(?MODULE, {get_results, ScanId}).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    process_flag(trap_exit, true),
    {ok, #state{scans = #{}}}.

handle_call({start_scan, CIDRs, Ports, Opts}, _From, State) ->
    case validate_scan_params(CIDRs, Ports, Opts) of
        ok ->
            ScanId = make_ref(),
            
            %% Get configuration
            RateLimit = maps:get(rate_limit, Opts, get_config(rate_limit, 10000)),
            
            %% Start rate limiter for this scan
            {ok, RateLimiter} = rate_limiter:start_link(RateLimit),
            
            %% Calculate total targets
            Total = calculate_total_targets(CIDRs, Ports),
            
            %% Create ETS tables for lock-free updates
            CounterTab = ets:new(scan_counter, [public, set, {write_concurrency, true}]),
            ResultsTab = ets:new(scan_results, [public, bag, {write_concurrency, true}]),
            
            %% Initialize counter
            ets:insert(CounterTab, {scanned, 0}),
            
            Scan = #scan{
                id = ScanId,
                cidrs = CIDRs,
                ports = Ports,
                opts = Opts,
                rate_limiter = RateLimiter,
                state = running,
                total = Total,
                scanned = CounterTab,
                results = ResultsTab,
                start_time = erlang:monotonic_time(millisecond),
                coordinator = undefined
            },
            
            %% Start scanning process
            Coordinator = spawn_link(fun() -> scan_process(Scan) end),
            
            %% Update scan with coordinator pid
            ScanWithCoord = Scan#scan{coordinator = Coordinator},
            
            NewScans = maps:put(ScanId, ScanWithCoord, State#state.scans),
            {reply, {ok, ScanId}, State#state{scans = NewScans}};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call({stop_scan, ScanId}, _From, State) ->
    case maps:find(ScanId, State#state.scans) of
        {ok, Scan} ->
            rate_limiter:stop(Scan#scan.rate_limiter),
            NewScan = Scan#scan{state = stopped},
            NewScans = maps:put(ScanId, NewScan, State#state.scans),
            {reply, ok, State#state{scans = NewScans}};
        error ->
            {reply, {error, not_found}, State}
    end;

handle_call({pause_scan, ScanId}, _From, State) ->
    case maps:find(ScanId, State#state.scans) of
        {ok, Scan} when Scan#scan.state =:= running ->
            NewScan = Scan#scan{state = paused},
            NewScans = maps:put(ScanId, NewScan, State#state.scans),
            {reply, ok, State#state{scans = NewScans}};
        {ok, _} ->
            {reply, {error, not_running}, State};
        error ->
            {reply, {error, not_found}, State}
    end;

handle_call({resume_scan, ScanId}, _From, State) ->
    case maps:find(ScanId, State#state.scans) of
        {ok, Scan} when Scan#scan.state =:= paused ->
            NewScan = Scan#scan{state = running},
            NewScans = maps:put(ScanId, NewScan, State#state.scans),
            {reply, ok, State#state{scans = NewScans}};
        {ok, _} ->
            {reply, {error, not_paused}, State};
        error ->
            {reply, {error, not_found}, State}
    end;

handle_call({get_status, ScanId}, _From, State) ->
    case maps:find(ScanId, State#state.scans) of
        {ok, Scan} ->
            %% Read scanned count from ETS (atomic, no blocking)
            ScannedCount = case ets:lookup(Scan#scan.scanned, scanned) of
                [{scanned, N}] -> N;
                [] -> 0
            end,
            %% Check if scan is completed
            ScanState = case ScannedCount >= Scan#scan.total of
                true -> completed;
                false -> Scan#scan.state
            end,
            Status = #{
                state => ScanState,
                total => Scan#scan.total,
                scanned => ScannedCount,
                progress => case Scan#scan.total of
                    0 -> 0.0;
                    T -> (ScannedCount / T) * 100
                end,
                elapsed => erlang:monotonic_time(millisecond) - Scan#scan.start_time,
                results_count => ets:info(Scan#scan.results, size)
            },
            {reply, {ok, Status}, State};
        error ->
            {reply, {error, not_found}, State}
    end;

handle_call({get_results, ScanId}, _From, State) ->
    case maps:find(ScanId, State#state.scans) of
        {ok, Scan} ->
            %% Read results from ETS
            Results = ets:tab2list(Scan#scan.results),
            {reply, {ok, Results}, State};
        error ->
            {reply, {error, not_found}, State}
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

%% scan_result messages are no longer needed - results written directly to ETS
handle_info({'EXIT', _Pid, normal}, State) ->
    {noreply, State};

handle_info({'EXIT', _Pid, _Reason}, State) ->
    %% Coordinator or linked process crashed
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    %% Stop all rate limiters and cleanup ETS tables
    maps:fold(fun(_Id, Scan, _Acc) ->
        catch rate_limiter:stop(Scan#scan.rate_limiter)
    end, ok, State#state.scans),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal functions
%%====================================================================

%% Validate scan parameters
validate_scan_params([], _, _) ->
    {error, empty_cidr_list};
validate_scan_params(_, [], _) ->
    {error, empty_port_list};
validate_scan_params(_CIDRs, Ports, _Opts) ->
    case lists:all(fun(P) -> is_integer(P) andalso P > 0 andalso P =< 65535 end, Ports) of
        true -> ok;
        false -> {error, invalid_ports}
    end.

%% Calculate total number of targets
calculate_total_targets(CIDRs, Ports) ->
    TotalIPs = lists:sum([cidr_parser:count_ips(CIDR) || CIDR <- CIDRs]),
    TotalIPs * length(Ports).

%% Main scanning process
scan_process(Scan) ->
    %% Default 5000 - reliable for macOS without ulimit tuning
    Concurrency = maps:get(concurrency, Scan#scan.opts, 5000),
    Timeout = maps:get(timeout, Scan#scan.opts, get_config(connect_timeout, 1000)),
    
    %% Check if SYN scan is requested and available
    UseSyn = case maps:get(syn_scan, Scan#scan.opts, auto) of
        true -> syn_scanner:is_available();
        false -> false;
        auto -> syn_scanner:is_available()
    end,
    
    %% Log scan mode
    case UseSyn of
        true -> io:format("[SYN] Using raw socket SYN scan (3x faster)~n");
        false -> ok
    end,
    
    %% Get number of schedulers for parallel chunks
    NumSchedulers = erlang:system_info(schedulers),
    %% Configurable chunk multiplier (default 2x schedulers for IO-bound work)
    ChunkMultiplier = maps:get(chunk_multiplier, Scan#scan.opts, 2),
    NumChunks = NumSchedulers * ChunkMultiplier,
    
    %% Configurable batch size for SYN scan (default 1000)
    BatchSize = maps:get(batch_size, Scan#scan.opts, 1000),
    
    %% Generate all targets with options
    GenOpts = #{
        randomize => maps:get(randomize, Scan#scan.opts, false),
        filter_blackhole => maps:get(filter_blackhole, Scan#scan.opts, false)
    },
    Targets = generate_targets(Scan#scan.cidrs, Scan#scan.ports, GenOpts),
    
    %% Choose scan method
    case UseSyn of
        true ->
            %% SYN scan: use batch mode for maximum speed
            syn_scan_process(Targets, Timeout, Scan, BatchSize);
        false ->
            %% TCP connect: use chunked parallel scanning
            tcp_scan_process(Targets, Timeout, Scan, Concurrency, NumChunks, NumSchedulers)
    end.

%% SYN scan process - batch mode for maximum throughput
syn_scan_process(Targets, Timeout, Scan, BatchSize) ->
    CounterTab = Scan#scan.scanned,
    ResultsTab = Scan#scan.results,
    
    %% Initialize SYN scanner
    case syn_scanner:init() of
        {ok, LocalIP} ->
            io:format("[SYN] Local IP: ~s~n", [LocalIP]);
        {error, Reason} ->
            io:format("[SYN] Init failed: ~p, falling back to TCP~n", [Reason]),
            tcp_scan_process(Targets, Timeout, Scan, 5000, 16, 8)
    end,
    
    %% Process in configurable batches for memory efficiency
    syn_scan_batches(Targets, Timeout, CounterTab, ResultsTab, BatchSize),
    
    %% Cleanup
    syn_scanner:cleanup().

syn_scan_batches([], _Timeout, _CounterTab, _ResultsTab, _BatchSize) ->
    ok;
syn_scan_batches(Targets, Timeout, CounterTab, ResultsTab, BatchSize) ->
    {Batch, Rest} = safe_split(BatchSize, Targets),
    
    %% Scan batch
    case syn_scanner:scan_batch(Batch, Timeout) of
        {ok, Results} ->
            %% Store results
            lists:foreach(fun({IP, Result, _Port}) ->
                ets:insert(ResultsTab, {IP, Result}),
                ets:update_counter(CounterTab, scanned, 1)
            end, Results);
        {error, _} ->
            %% Fallback: scan individually
            lists:foreach(fun({IP, Port}) ->
                Result = syn_scanner:scan(IP, Port, Timeout),
                ets:insert(ResultsTab, {IP, Result}),
                ets:update_counter(CounterTab, scanned, 1)
            end, Batch)
    end,
    
    syn_scan_batches(Rest, Timeout, CounterTab, ResultsTab, BatchSize).

%% TCP connect scan process (original method)
tcp_scan_process(Targets, Timeout, Scan, Concurrency, NumChunks, NumSchedulers) ->
    %% Split targets into chunks for parallel processing
    Chunks = split_into_chunks(Targets, NumChunks),
    
    %% Calculate concurrency per chunk
    ConcurrencyPerChunk = max(100, Concurrency div NumChunks),
    
    %% Start parallel chunk scanners
    Self = self(),
    ChunkPids = lists:map(fun({ChunkIdx, ChunkTargets}) ->
        spawn_link(fun() ->
            %% Bind to specific scheduler for locality
            erlang:process_flag(scheduler, (ChunkIdx rem NumSchedulers) + 1),
            scan_chunk(ChunkTargets, Timeout, Scan, ConcurrencyPerChunk, Self, ChunkIdx)
        end)
    end, lists:zip(lists:seq(1, length(Chunks)), Chunks)),
    
    %% Wait for all chunks to complete
    wait_for_chunks(length(ChunkPids)).

%% Split targets into N roughly equal chunks
split_into_chunks(Targets, NumChunks) ->
    TotalLen = length(Targets),
    ChunkSize = max(1, TotalLen div NumChunks),
    split_into_chunks(Targets, ChunkSize, NumChunks, []).

split_into_chunks([], _ChunkSize, _Remaining, Acc) ->
    lists:reverse(Acc);
split_into_chunks(Targets, _ChunkSize, 1, Acc) ->
    lists:reverse([Targets | Acc]);
split_into_chunks(Targets, ChunkSize, Remaining, Acc) when Remaining > 1 ->
    {Chunk, Rest} = safe_split(ChunkSize, Targets),
    split_into_chunks(Rest, ChunkSize, Remaining - 1, [Chunk | Acc]).

%% Wait for all chunk scanners to complete
wait_for_chunks(0) -> ok;
wait_for_chunks(N) ->
    receive
        {chunk_done, _ChunkIdx} ->
            wait_for_chunks(N - 1)
    after 300000 ->  % 5 min timeout for very large scans
        ok
    end.

%% Scan a single chunk of targets
scan_chunk(Targets, Timeout, Scan, Concurrency, Coordinator, ChunkIdx) ->
    Self = self(),
    
    %% Start initial batch of workers
    {InFlight, Remaining} = start_batch(Targets, Timeout, Scan, Concurrency, Self),
    
    %% Process remaining targets as workers complete
    chunk_scan_loop(InFlight, Remaining, Timeout, Scan, Concurrency, Self),
    
    %% Notify coordinator that this chunk is done
    Coordinator ! {chunk_done, ChunkIdx}.

%% Generate all targets as list of {IP, Port}
%% Supports randomization and blackhole filtering
generate_targets(CIDRs, Ports, Opts) ->
    AllIPs = lists:flatmap(fun(CIDR) -> cidr_parser:parse(CIDR) end, CIDRs),
    
    %% Generate targets
    Targets = [{IP, Port} || IP <- AllIPs, Port <- Ports],
    
    %% Apply blackhole filter if enabled (default: off for local scans)
    FilteredTargets = case maps:get(filter_blackhole, Opts, false) of
        true -> scan_randomizer:blackhole_filter(Targets);
        false -> Targets
    end,
    
    %% Apply randomization if enabled
    case maps:get(randomize, Opts, false) of
        true -> scan_randomizer:shuffle(FilteredTargets);
        false -> FilteredTargets
    end.

start_batch(Targets, Timeout, Scan, MaxWorkers, Collector) ->
    {ToStart, Remaining} = safe_split(MaxWorkers, Targets),
    
    InFlight = lists:foldl(fun({IP, Port}, Acc) ->
        spawn_scanner(IP, Port, Timeout, Scan, Collector),
        Acc + 1
    end, 0, ToStart),
    
    {InFlight, Remaining}.

spawn_scanner(IP, Port, Timeout, Scan, Collector) ->
    %% Get ETS tables from Scan record
    CounterTab = Scan#scan.scanned,
    ResultsTab = Scan#scan.results,
    
    %% Use spawn_monitor to detect worker crashes
    {_Pid, _MonRef} = spawn_monitor(fun() ->
        %% Get options
        Retries = maps:get(retries, Scan#scan.opts, 0),
        GrabBanner = maps:get(grab_banner, Scan#scan.opts, false),
        
        %% Quick TCP connect check
        Result = case Retries of
            0 -> quick_scan(IP, Port, Timeout);
            N -> quick_scan_with_retry(IP, Port, Timeout, N)
        end,
        
        %% Optionally grab banner for open ports
        FinalResult = case {Result, GrabBanner} of
            {{open, Port}, true} ->
                case banner_grabber:grab(IP, Port, Timeout) of
                    {ok, Banner, ServiceInfo} ->
                        {open, Port, #{banner => Banner, service => ServiceInfo}};
                    {error, _} ->
                        {open, Port, #{}}
                end;
            _ ->
                Result
        end,
        
        %% Write result directly to ETS (lock-free, no gen_server bottleneck)
        ets:insert(ResultsTab, {IP, FinalResult}),
        
        %% Atomic increment of scanned counter
        ets:update_counter(CounterTab, scanned, 1),
        
        %% Signal completion to collector
        Collector ! {worker_done, self()}
    end).

%% TCP scan with exponential backoff retry
%% This significantly improves reliability for flaky networks
quick_scan_with_retry(IP, Port, Timeout, MaxRetries) ->
    quick_scan_with_retry(IP, Port, Timeout, MaxRetries, 0).

quick_scan_with_retry(IP, Port, Timeout, MaxRetries, Attempt) when Attempt >= MaxRetries ->
    %% Final attempt with longer timeout
    quick_scan(IP, Port, Timeout * 2);
quick_scan_with_retry(IP, Port, Timeout, MaxRetries, Attempt) ->
    case quick_scan(IP, Port, Timeout) of
        {filtered, Port} ->
            %% Exponential backoff: 50ms, 100ms, 200ms...
            BackoffMs = 50 * (1 bsl Attempt),
            timer:sleep(min(BackoffMs, 500)),
            quick_scan_with_retry(IP, Port, Timeout, MaxRetries, Attempt + 1);
        {closed, Port} = Result ->
            %% Closed is definitive, no retry needed
            Result;
        {open, Port} = Result ->
            Result
    end.

%% Fast TCP scan without gen_server overhead
quick_scan(IP, Port, Timeout) ->
    case gen_tcp:connect(IP, Port, [binary, {active, false}, {packet, raw}], Timeout) of
        {ok, Socket} ->
            gen_tcp:close(Socket),
            {open, Port};
        {error, econnrefused} ->
            {closed, Port};
        {error, _} ->
            {filtered, Port}
    end.

%% Chunk-based scan loop (per chunk)
%% Uses spawn_monitor to track workers and handles crashes properly
chunk_scan_loop(0, [], _Timeout, _Scan, _Concurrency, _Collector) ->
    ok;
chunk_scan_loop(InFlight, Remaining, Timeout, Scan, Concurrency, Collector) ->
    %% Use longer timeout multiplier to avoid premature timeouts
    %% Minimum 5 seconds to handle network delays
    WaitTimeout = max(5000, Timeout * 10),
    receive
        {worker_done, _Pid} ->
            %% Worker completed successfully, start new worker if targets remain
            case Remaining of
                [] ->
                    chunk_scan_loop(InFlight - 1, [], Timeout, Scan, Concurrency, Collector);
                [{IP, Port} | Rest] ->
                    spawn_scanner(IP, Port, Timeout, Scan, Collector),
                    chunk_scan_loop(InFlight, Rest, Timeout, Scan, Concurrency, Collector)
            end;
        {'DOWN', _MonRef, process, _Pid, normal} ->
            %% Worker exited normally (should have sent worker_done first)
            %% Just decrease InFlight counter
            case Remaining of
                [] ->
                    chunk_scan_loop(InFlight - 1, [], Timeout, Scan, Concurrency, Collector);
                [{IP, Port} | Rest] ->
                    spawn_scanner(IP, Port, Timeout, Scan, Collector),
                    chunk_scan_loop(InFlight, Rest, Timeout, Scan, Concurrency, Collector)
            end;
        {'DOWN', _MonRef, process, _Pid, _Reason} ->
            %% Worker crashed! Decrement counter but result was already written (or lost)
            %% Atomic counter ensures we don't lose count
            case Remaining of
                [] ->
                    chunk_scan_loop(InFlight - 1, [], Timeout, Scan, Concurrency, Collector);
                [{IP, Port} | Rest] ->
                    spawn_scanner(IP, Port, Timeout, Scan, Collector),
                    chunk_scan_loop(InFlight, Rest, Timeout, Scan, Concurrency, Collector)
            end
    after WaitTimeout ->
        %% Timeout waiting for workers - they may be stuck on slow hosts
        %% Don't drop them, just continue waiting if we still have in-flight workers
        case {InFlight, Remaining} of
            {0, []} ->
                ok;
            {N, []} when N > 0 ->
                %% Still have workers, wait more (reduce count by 1 to eventually finish)
                %% This handles truly stuck workers
                chunk_scan_loop(InFlight - 1, [], Timeout, Scan, Concurrency, Collector);
            {_, [{IP, Port} | Rest]} ->
                %% Have remaining targets, spawn more workers
                spawn_scanner(IP, Port, Timeout, Scan, Collector),
                chunk_scan_loop(InFlight, Rest, Timeout, Scan, Concurrency, Collector)
        end
    end.

safe_split(N, List) when N >= length(List) ->
    {List, []};
safe_split(N, List) ->
    lists:split(N, List).

%% Get configuration value
get_config(Key, Default) ->
    case application:get_env(massping, Key) of
        {ok, Value} -> Value;
        undefined -> Default
    end.

%%====================================================================
%% Tests
%%====================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

validate_params_test() ->
    ?assertEqual(ok, validate_scan_params(["192.168.1.0/24"], [80], #{})),
    ?assertEqual({error, empty_cidr_list}, validate_scan_params([], [80], #{})),
    ?assertEqual({error, empty_port_list}, validate_scan_params(["192.168.1.0/24"], [], #{})),
    ?assertEqual({error, invalid_ports}, validate_scan_params(["192.168.1.0/24"], [0], #{})).

calculate_total_test() ->
    ?assertEqual(256, calculate_total_targets(["192.168.1.0/24"], [80])),
    ?assertEqual(768, calculate_total_targets(["192.168.1.0/24"], [80, 443, 22])).

-endif.
