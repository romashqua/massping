%%%-------------------------------------------------------------------
%%% @doc MassPing Scan Manager
%%% Manages active scans for REST API
%%% @end
%%%-------------------------------------------------------------------
-module(massping_scan_manager).
-behaviour(gen_server).

%% API
-export([
    start_link/0,
    start_scan/3,
    stop_scan/1,
    get_scan/1,
    get_results/1,
    list_scans/0,
    resume_scan/1
]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(SERVER, ?MODULE).

-record(state, {
    scans = #{} :: #{binary() => scan_info()},
    results_table :: ets:tid()
}).

-type scan_info() :: #{
    id := binary(),
    cidrs := [binary()],
    ports := [integer()],
    status := running | completed | stopped | failed,
    progress := float(),
    started_at := integer(),
    completed_at => integer(),
    total_targets := integer(),
    scanned := integer(),
    open_ports := integer()
}.

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec start_scan([binary()], [integer()], map()) -> {ok, binary()} | {error, term()}.
start_scan(CIDRs, Ports, Options) ->
    gen_server:call(?SERVER, {start_scan, CIDRs, Ports, Options}).

-spec stop_scan(binary()) -> ok | {error, term()}.
stop_scan(ScanId) ->
    gen_server:call(?SERVER, {stop_scan, ScanId}).

-spec get_scan(binary()) -> {ok, scan_info()} | {error, not_found}.
get_scan(ScanId) ->
    gen_server:call(?SERVER, {get_scan, ScanId}).

-spec get_results(binary()) -> {ok, list()} | {error, term()}.
get_results(ScanId) ->
    gen_server:call(?SERVER, {get_results, ScanId}).

-spec list_scans() -> [scan_info()].
list_scans() ->
    gen_server:call(?SERVER, list_scans).

-spec resume_scan(map()) -> {ok, binary()} | {error, term()}.
resume_scan(State) ->
    gen_server:call(?SERVER, {resume_scan, State}).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    ResultsTable = ets:new(scan_results, [set, public, {write_concurrency, true}]),
    {ok, #state{results_table = ResultsTable}}.

handle_call({start_scan, CIDRs, Ports, Options}, _From, State) ->
    ScanId = generate_scan_id(),
    
    %% Convert binary CIDRs to strings
    CIDRList = [binary_to_list(C) || C <- CIDRs],
    PortList = Ports,
    
    %% Parse options
    Opts = #{
        concurrency => maps:get(<<"concurrency">>, Options, 5000),
        timeout => maps:get(<<"timeout">>, Options, 1000),
        retries => maps:get(<<"retries">>, Options, 0)
    },
    
    %% Start scan via massping_core (returns {ok, CoreScanRef})
    case massping_core:start_scan(CIDRList, PortList, Opts) of
        {ok, CoreScanRef} ->
            ScanInfo = #{
                id => ScanId,
                core_ref => CoreScanRef,
                cidrs => CIDRs,
                ports => Ports,
                status => running,
                progress => 0.0,
                started_at => erlang:system_time(second),
                total_targets => 0,
                scanned => 0,
                open_ports => 0
            },
            
            %% Start status polling
            Self = self(),
            spawn_link(fun() -> poll_scan_status(Self, ScanId, CoreScanRef) end),
            
            NewState = State#state{
                scans = maps:put(ScanId, ScanInfo, State#state.scans)
            },
            
            {reply, {ok, ScanId}, NewState};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call({stop_scan, ScanId}, _From, State) ->
    case maps:get(ScanId, State#state.scans, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        ScanInfo ->
            %% TODO: Actually stop the scan process
            UpdatedInfo = ScanInfo#{status => stopped},
            NewScans = maps:put(ScanId, UpdatedInfo, State#state.scans),
            {reply, ok, State#state{scans = NewScans}}
    end;

handle_call({get_scan, ScanId}, _From, State) ->
    case maps:get(ScanId, State#state.scans, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        ScanInfo ->
            %% Remove internal fields
            PublicInfo = maps:without([core_ref], ScanInfo),
            {reply, {ok, PublicInfo}, State}
    end;

handle_call({get_results, ScanId}, _From, State) ->
    case maps:get(ScanId, State#state.scans, undefined) of
        undefined ->
            {reply, {error, not_found}, State};
        #{core_ref := CoreRef} ->
            case massping_core:get_results(CoreRef) of
                {ok, Results} ->
                    FormattedResults = [format_result(R) || R <- Results],
                    {reply, {ok, FormattedResults}, State};
                {error, Reason} ->
                    {reply, {error, Reason}, State}
            end;
        _ ->
            {reply, {ok, []}, State}
    end;

handle_call(list_scans, _From, State) ->
    ScanList = [maps:without([core_ref], Info) || 
                {_, Info} <- maps:to_list(State#state.scans)],
    {reply, ScanList, State};

handle_call({resume_scan, SavedState}, _From, State) ->
    %% Extract saved scan info and start resumed scan
    CIDRs = maps:get(cidrs, SavedState, []),
    Ports = maps:get(ports, SavedState, []),
    Options0 = maps:get(options, SavedState, #{}),
    CompletedChunks = maps:get(completed_chunks, SavedState, []),
    
    %% Mark completed chunks to skip
    Options = Options0#{completed_chunks => CompletedChunks},
    
    %% Start scan with resumed state
    ScanId = generate_scan_id(),
    
    case massping_core:start_scan(CIDRs, Ports, Options) of
        {ok, _ScanRef} ->
            ScanInfo = #{
                id => ScanId,
                cidrs => CIDRs,
                ports => Ports,
                state => running,
                resumed => true,
                started_at => erlang:system_time(second)
            },
            NewScans = maps:put(ScanId, ScanInfo, State#state.scans),
            {reply, {ok, ScanId}, State#state{scans = NewScans}};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({scan_status_update, ScanId, StatusInfo}, State) ->
    case maps:get(ScanId, State#state.scans, undefined) of
        undefined ->
            {noreply, State};
        ScanInfo ->
            UpdatedInfo = ScanInfo#{
                status => maps:get(state, StatusInfo, running),
                progress => maps:get(progress, StatusInfo, 0.0),
                total_targets => maps:get(total, StatusInfo, 0),
                scanned => maps:get(scanned, StatusInfo, 0),
                open_ports => maps:get(results_count, StatusInfo, 0)
            },
            NewScans = maps:put(ScanId, UpdatedInfo, State#state.scans),
            {noreply, State#state{scans = NewScans}}
    end;

handle_info({scan_completed, ScanId, OpenCount}, State) ->
    case maps:get(ScanId, State#state.scans, undefined) of
        undefined ->
            {noreply, State};
        ScanInfo ->
            UpdatedInfo = ScanInfo#{
                status => completed,
                progress => 100.0,
                completed_at => erlang:system_time(second),
                open_ports => OpenCount
            },
            NewScans = maps:put(ScanId, UpdatedInfo, State#state.scans),
            {noreply, State#state{scans = NewScans}}
    end;

handle_info({scan_failed, ScanId, _Error}, State) ->
    case maps:get(ScanId, State#state.scans, undefined) of
        undefined ->
            {noreply, State};
        ScanInfo ->
            UpdatedInfo = ScanInfo#{status => failed},
            NewScans = maps:put(ScanId, UpdatedInfo, State#state.scans),
            {noreply, State#state{scans = NewScans}}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================

generate_scan_id() ->
    Bytes = crypto:strong_rand_bytes(8),
    Base = base64:encode(Bytes),
    %% Remove non-URL-safe characters
    binary:replace(Base, [<<"+">>, <<"/">>, <<"=">>], <<>>, [global]).

format_result({IP, Status, Port}) ->
    #{
        ip => format_ip(IP),
        port => Port,
        status => Status
    };
format_result({IP, Status, Port, Banner}) ->
    #{
        ip => format_ip(IP),
        port => Port,
        status => Status,
        banner => Banner
    };
format_result(Other) ->
    Other.

format_ip({A, B, C, D}) ->
    list_to_binary(io_lib:format("~B.~B.~B.~B", [A, B, C, D]));
format_ip(IP) when is_list(IP) ->
    list_to_binary(IP);
format_ip(IP) ->
    IP.

%% Poll massping_core for scan status updates
poll_scan_status(Manager, ScanId, CoreRef) ->
    poll_scan_status_loop(Manager, ScanId, CoreRef).

poll_scan_status_loop(Manager, ScanId, CoreRef) ->
    timer:sleep(500),  %% Poll every 500ms
    case massping_core:get_status(CoreRef) of
        {ok, StatusInfo} ->
            Manager ! {scan_status_update, ScanId, StatusInfo},
            case maps:get(state, StatusInfo, running) of
                completed ->
                    ResultsCount = maps:get(results_count, StatusInfo, 0),
                    Manager ! {scan_completed, ScanId, ResultsCount};
                stopped ->
                    ok;
                failed ->
                    Manager ! {scan_failed, ScanId, unknown};
                _ ->
                    poll_scan_status_loop(Manager, ScanId, CoreRef)
            end;
        {error, _} ->
            Manager ! {scan_failed, ScanId, core_error}
    end.
