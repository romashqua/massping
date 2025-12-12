%%%-------------------------------------------------------------------
%%% @doc MassPing Prometheus Metrics
%%% Exports metrics for Prometheus/Grafana monitoring
%%% @end
%%%-------------------------------------------------------------------
-module(massping_metrics).

-export([
    setup/0,
    inc_scanned/1,
    inc_open_ports/1,
    inc_closed_ports/1,
    inc_filtered_ports/1,
    observe_scan_duration/1,
    set_active_scans/1,
    set_scan_rate/1,
    get_metrics/0
]).

%% Metrics state (using process dictionary for simplicity)
%% In production, use prometheus_* libraries

-define(METRICS_TABLE, massping_metrics).

%%====================================================================
%% API
%%====================================================================

%% @doc Setup metrics (create ETS table)
setup() ->
    case ets:whereis(?METRICS_TABLE) of
        undefined ->
            ets:new(?METRICS_TABLE, [named_table, public, {write_concurrency, true}]),
            %% Initialize counters
            ets:insert(?METRICS_TABLE, [
                {targets_scanned_total, 0},
                {open_ports_total, 0},
                {closed_ports_total, 0},
                {filtered_ports_total, 0},
                {active_scans, 0},
                {scan_rate, 0.0},
                {scan_duration_sum, 0.0},
                {scan_duration_count, 0}
            ]),
            ok;
        _ ->
            ok
    end.

%% @doc Increment scanned targets counter
inc_scanned(N) ->
    catch ets:update_counter(?METRICS_TABLE, targets_scanned_total, N).

%% @doc Increment open ports counter
inc_open_ports(N) ->
    catch ets:update_counter(?METRICS_TABLE, open_ports_total, N).

%% @doc Increment closed ports counter
inc_closed_ports(N) ->
    catch ets:update_counter(?METRICS_TABLE, closed_ports_total, N).

%% @doc Increment filtered ports counter
inc_filtered_ports(N) ->
    catch ets:update_counter(?METRICS_TABLE, filtered_ports_total, N).

%% @doc Observe scan duration
observe_scan_duration(DurationMs) ->
    catch ets:update_counter(?METRICS_TABLE, scan_duration_sum, DurationMs),
    catch ets:update_counter(?METRICS_TABLE, scan_duration_count, 1).

%% @doc Set active scans gauge
set_active_scans(N) ->
    catch ets:insert(?METRICS_TABLE, {active_scans, N}).

%% @doc Set current scan rate
set_scan_rate(Rate) ->
    catch ets:insert(?METRICS_TABLE, {scan_rate, Rate}).

%% @doc Get all metrics in Prometheus text format
get_metrics() ->
    setup(),
    Metrics = ets:tab2list(?METRICS_TABLE),
    MetricsMap = maps:from_list(Metrics),
    
    %% Generate Prometheus exposition format
    Lines = [
        "# HELP massping_targets_scanned_total Total number of targets scanned",
        "# TYPE massping_targets_scanned_total counter",
        io_lib:format("massping_targets_scanned_total ~B", 
                      [maps:get(targets_scanned_total, MetricsMap, 0)]),
        "",
        "# HELP massping_open_ports_total Total number of open ports found",
        "# TYPE massping_open_ports_total counter",
        io_lib:format("massping_open_ports_total ~B", 
                      [maps:get(open_ports_total, MetricsMap, 0)]),
        "",
        "# HELP massping_closed_ports_total Total number of closed ports",
        "# TYPE massping_closed_ports_total counter",
        io_lib:format("massping_closed_ports_total ~B", 
                      [maps:get(closed_ports_total, MetricsMap, 0)]),
        "",
        "# HELP massping_filtered_ports_total Total number of filtered ports",
        "# TYPE massping_filtered_ports_total counter",
        io_lib:format("massping_filtered_ports_total ~B", 
                      [maps:get(filtered_ports_total, MetricsMap, 0)]),
        "",
        "# HELP massping_active_scans Current number of active scans",
        "# TYPE massping_active_scans gauge",
        io_lib:format("massping_active_scans ~B", 
                      [maps:get(active_scans, MetricsMap, 0)]),
        "",
        "# HELP massping_scan_rate_per_second Current scan rate",
        "# TYPE massping_scan_rate_per_second gauge",
        io_lib:format("massping_scan_rate_per_second ~.2f", 
                      [float(maps:get(scan_rate, MetricsMap, 0))]),
        "",
        "# HELP massping_scan_duration_seconds Scan duration histogram",
        "# TYPE massping_scan_duration_seconds summary",
        io_lib:format("massping_scan_duration_seconds_sum ~.3f", 
                      [float(maps:get(scan_duration_sum, MetricsMap, 0)) / 1000]),
        io_lib:format("massping_scan_duration_seconds_count ~B", 
                      [maps:get(scan_duration_count, MetricsMap, 0)]),
        "",
        "# HELP massping_info MassPing version info",
        "# TYPE massping_info gauge",
        "massping_info{version=\"1.0.0\"} 1",
        ""
    ],
    
    iolist_to_binary(string:join(Lines, "\n")).
