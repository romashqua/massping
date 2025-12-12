%%%-------------------------------------------------------------------
%%% @doc MassPing command-line interface and public API
%%% @end
%%%-------------------------------------------------------------------
-module(massping).

-export([
    main/1,  % escript entry point
    scan/2,
    scan/3,
    stop/1,
    status/1,
    results/1
]).

%%====================================================================
%% Public API
%%====================================================================

%% @doc Simple scan with default options
-spec scan(string() | [string()], [pos_integer()]) -> 
    {ok, reference()} | {error, term()}.
scan(CIDR, Ports) when is_list(CIDR), is_integer(hd(CIDR)) ->
    scan([CIDR], Ports, #{});
scan(CIDRs, Ports) when is_list(CIDRs) ->
    scan(CIDRs, Ports, #{}).

%% @doc Scan with custom options
-spec scan(string() | [string()], [pos_integer()], map()) ->
    {ok, reference()} | {error, term()}.
scan(CIDR, Ports, Opts) when is_list(CIDR), is_integer(hd(CIDR)) ->
    scan([CIDR], Ports, Opts);
scan(CIDRs, Ports, Opts) ->
    ensure_started(),
    massping_core:start_scan(CIDRs, Ports, Opts).

%% @doc Stop a scan
-spec stop(reference()) -> ok | {error, term()}.
stop(ScanRef) ->
    massping_core:stop_scan(ScanRef).

%% @doc Get scan status
-spec status(reference()) -> {ok, map()} | {error, term()}.
status(ScanRef) ->
    massping_core:get_status(ScanRef).

%% @doc Get scan results
-spec results(reference()) -> {ok, [term()]} | {error, term()}.
results(ScanRef) ->
    massping_core:get_results(ScanRef).

%%====================================================================
%% Escript entry point
%%====================================================================

%% @doc Main entry point for escript
main(Args) ->
    case parse_args(Args) of
        {ok, Command, Params} ->
            ensure_started(),
            execute_command(Command, Params);
        {error, Reason} ->
            print_error(Reason),
            print_usage(),
            halt(1)
    end.

%%====================================================================
%% Internal functions
%%====================================================================

%% Ensure application is started
ensure_started() ->
    case application:ensure_all_started(massping) of
        {ok, _} -> ok;
        {error, Reason} ->
            io:format("Failed to start MassPing: ~p~n", [Reason]),
            halt(1)
    end.

%% Parse command-line arguments
parse_args([]) ->
    {error, no_command};
parse_args(["scan" | Rest]) ->
    parse_scan_args(Rest);
parse_args(["web" | Rest]) ->
    parse_web_args(Rest);
parse_args(["sessions" | _]) ->
    {ok, scan, #{opts => #{list_sessions => true}}};
parse_args(["resume", SessionId | Rest]) ->
    Opts = parse_resume_options(Rest, #{}),
    {ok, scan, #{opts => Opts#{resume => SessionId}}};
parse_args(["resume" | _]) ->
    {error, "Usage: massping resume <session-id>"};
parse_args(["help" | _]) ->
    {ok, help, #{}};
parse_args(["--web" | Rest]) ->
    parse_web_args(Rest);
parse_args(["--help" | _]) ->
    {ok, help, #{}};
parse_args(["-h" | _]) ->
    {ok, help, #{}};
parse_args([Unknown | _]) ->
    {error, {unknown_command, Unknown}}.

%% Parse web command arguments
parse_web_args(Args) ->
    Opts = parse_web_options(Args, #{start_web => true, web_port => 8080}),
    {ok, scan, #{opts => Opts}}.

parse_web_options([], Acc) ->
    Acc;
parse_web_options(["--port", Port | Rest], Acc) ->
    parse_web_options(Rest, Acc#{web_port => list_to_integer(Port)});
parse_web_options(["--web-port", Port | Rest], Acc) ->
    parse_web_options(Rest, Acc#{web_port => list_to_integer(Port)});
parse_web_options(["-p", Port | Rest], Acc) ->
    parse_web_options(Rest, Acc#{web_port => list_to_integer(Port)});
parse_web_options([_ | Rest], Acc) ->
    parse_web_options(Rest, Acc).

%% Parse resume options
parse_resume_options([], Acc) ->
    Acc;
parse_resume_options([_ | Rest], Acc) ->
    parse_resume_options(Rest, Acc).

%% Parse scan command arguments
parse_scan_args(Args) ->
    try
        Opts = parse_options(Args, #{cidrs => [], ports => []}),
        
        case {maps:get(cidrs, Opts), maps:get(ports, Opts)} of
            {[], _} -> {error, no_cidrs_specified};
            {_, []} -> {error, no_ports_specified};
            {CIDRs, Ports} ->
                ScanOpts = maps:without([cidrs, ports], Opts),
                {ok, scan, #{cidrs => CIDRs, ports => Ports, opts => ScanOpts}}
        end
    catch
        _:_ -> {error, invalid_arguments}
    end.

%% Parse command-line options
parse_options([], Acc) ->
    Acc;
parse_options(["-p", PortsStr | Rest], Acc) ->
    Ports = parse_ports(PortsStr),
    parse_options(Rest, Acc#{ports => Ports});
parse_options(["--ports", PortsStr | Rest], Acc) ->
    Ports = parse_ports(PortsStr),
    parse_options(Rest, Acc#{ports => Ports});
parse_options(["-t", TimeoutStr | Rest], Acc) ->
    Timeout = list_to_integer(TimeoutStr),
    parse_options(Rest, Acc#{timeout => Timeout});
parse_options(["--timeout", TimeoutStr | Rest], Acc) ->
    Timeout = list_to_integer(TimeoutStr),
    parse_options(Rest, Acc#{timeout => Timeout});
parse_options(["-c", ConcStr | Rest], Acc) ->
    Conc = list_to_integer(ConcStr),
    parse_options(Rest, Acc#{concurrency => Conc});
parse_options(["--concurrency", ConcStr | Rest], Acc) ->
    Conc = list_to_integer(ConcStr),
    parse_options(Rest, Acc#{concurrency => Conc});
parse_options(["-r", RetryStr | Rest], Acc) ->
    Retry = list_to_integer(RetryStr),
    parse_options(Rest, Acc#{retries => Retry});
parse_options(["--retries", RetryStr | Rest], Acc) ->
    Retry = list_to_integer(RetryStr),
    parse_options(Rest, Acc#{retries => Retry});
parse_options(["--rate", RateStr | Rest], Acc) ->
    Rate = list_to_integer(RateStr),
    parse_options(Rest, Acc#{rate_limit => Rate});
parse_options(["-o", Output | Rest], Acc) ->
    parse_options(Rest, Acc#{output => Output});
parse_options(["--output", Output | Rest], Acc) ->
    parse_options(Rest, Acc#{output => Output});
parse_options(["--format", Format | Rest], Acc) ->
    parse_options(Rest, Acc#{format => list_to_atom(Format)});
parse_options(["--no-retry" | Rest], Acc) ->
    parse_options(Rest, Acc#{retries => 0});
%% SYN scan options (requires root)
parse_options(["--syn" | Rest], Acc) ->
    parse_options(Rest, Acc#{syn_scan => true});
parse_options(["--no-syn" | Rest], Acc) ->
    parse_options(Rest, Acc#{syn_scan => false});
%% Exclude file option
parse_options(["--exclude-file", ExcludeFile | Rest], Acc) ->
    parse_options(Rest, Acc#{exclude_file => ExcludeFile});
parse_options(["--exclude", ExcludeCIDR | Rest], Acc) ->
    Excludes = maps:get(excludes, Acc, []),
    parse_options(Rest, Acc#{excludes => [ExcludeCIDR | Excludes]});
%% Resume/save session options
parse_options(["--resume", SessionId | Rest], Acc) ->
    parse_options(Rest, Acc#{resume => SessionId});
parse_options(["--save-session", SessionId | Rest], Acc) ->
    parse_options(Rest, Acc#{save_session => SessionId});
parse_options(["--list-sessions" | Rest], Acc) ->
    parse_options(Rest, Acc#{list_sessions => true});
%% UDP scan
parse_options(["--udp" | Rest], Acc) ->
    parse_options(Rest, Acc#{udp_scan => true});
%% Output format options
parse_options(["--xml" | Rest], Acc) ->
    parse_options(Rest, Acc#{format => xml});
parse_options(["--grep" | Rest], Acc) ->
    parse_options(Rest, Acc#{format => grepable});
%% Web server
parse_options(["--web" | Rest], Acc) ->
    parse_options(Rest, Acc#{start_web => true});
parse_options(["--web-port", PortStr | Rest], Acc) ->
    parse_options(Rest, Acc#{start_web => true, web_port => list_to_integer(PortStr)});
%% New options for improved scanning
parse_options(["--randomize" | Rest], Acc) ->
    parse_options(Rest, Acc#{randomize => true});
parse_options(["--no-randomize" | Rest], Acc) ->
    parse_options(Rest, Acc#{randomize => false});
parse_options(["--filter-blackhole" | Rest], Acc) ->
    parse_options(Rest, Acc#{filter_blackhole => true});
parse_options(["--grab-banner" | Rest], Acc) ->
    parse_options(Rest, Acc#{grab_banner => true});
parse_options(["--stealth" | Rest], Acc) ->
    %% Stealth mode: randomize + slow rate + longer timeout
    parse_options(Rest, Acc#{
        randomize => true,
        rate_limit => 100,
        timeout => 5000,
        concurrency => 500
    });
parse_options(["--aggressive" | Rest], Acc) ->
    %% Aggressive mode: MAXIMUM SPEED
    %% - Max concurrency for fast scanning
    %% - Short timeout (500ms) - enough for most hosts
    %% - 1 retry for reliability
    parse_options(Rest, Acc#{
        concurrency => 50000,
        timeout => 500,
        retries => 1
    });
parse_options(["--ultra" | Rest], Acc) ->
    %% Ultra mode: balanced speed/reliability
    parse_options(Rest, Acc#{
        concurrency => 20000,
        timeout => 800,
        retries => 2
    });
parse_options(["--turbo" | Rest], Acc) ->
    %% Turbo mode: insane speed, LAN only, may miss hosts
    parse_options(Rest, Acc#{
        concurrency => 50000,
        timeout => 300,
        retries => 0,
        batch_size => 5000,
        chunk_multiplier => 4
    });
parse_options(["--adaptive" | Rest], Acc) ->
    parse_options(Rest, Acc#{adaptive => true});
parse_options(["--batch-size", SizeStr | Rest], Acc) ->
    Size = list_to_integer(SizeStr),
    parse_options(Rest, Acc#{batch_size => Size});
parse_options(["--chunks", MultStr | Rest], Acc) ->
    Mult = list_to_integer(MultStr),
    parse_options(Rest, Acc#{chunk_multiplier => Mult});
parse_options([CIDR | Rest], Acc) ->
    CIDRs = maps:get(cidrs, Acc, []),
    parse_options(Rest, Acc#{cidrs => [CIDR | CIDRs]}).

%% Parse ports string
parse_ports(PortsStr) ->
    PortStrs = string:tokens(PortsStr, ","),
    [list_to_integer(string:trim(P)) || P <- PortStrs].

%% Execute command
execute_command(help, _Params) ->
    print_usage(),
    halt(0);
execute_command(scan, #{opts := #{list_sessions := true}}) ->
    %% List saved sessions
    Sessions = scan_state:list_sessions(),
    case Sessions of
        [] ->
            io:format("No saved sessions found.~n");
        _ ->
            io:format("Saved sessions:~n"),
            io:format("--------------------------------------------------------------------------------~n"),
            io:format("  ~-20s ~-25s ~s~n", ["Session ID", "Last Updated", "Progress"]),
            io:format("--------------------------------------------------------------------------------~n"),
            lists:foreach(fun({Id, Ts, Progress}) ->
                DateTime = calendar:system_time_to_local_time(Ts, second),
                {{Y,M,D},{H,Mi,S}} = DateTime,
                TimeStr = io_lib:format("~4..0B-~2..0B-~2..0B ~2..0B:~2..0B:~2..0B", [Y,M,D,H,Mi,S]),
                io:format("  ~-20s ~-25s ~.1f%~n", [Id, TimeStr, Progress])
            end, Sessions)
    end,
    halt(0);
execute_command(scan, #{opts := #{resume := SessionId} = Opts} = Params) ->
    %% Resume from saved session
    io:format("Resuming session: ~s~n", [SessionId]),
    case scan_state:load(SessionId) of
        {ok, State} ->
            CIDRs = maps:get(cidrs, State),
            Ports = maps:get(ports, State),
            SavedOpts = maps:get(options, State, #{}),
            MergedOpts = maps:merge(SavedOpts, Opts),
            execute_command(scan, Params#{cidrs => CIDRs, ports => Ports, opts => MergedOpts});
        {error, Reason} ->
            io:format("Failed to load session: ~p~n", [Reason]),
            halt(1)
    end;
execute_command(scan, #{opts := #{start_web := true} = Opts}) ->
    %% Start web server
    Port = maps:get(web_port, Opts, 8080),
    case massping_web:start(#{port => Port}) of
        {ok, _} ->
            io:format("Web server started. Press Ctrl+C to stop.~n"),
            %% Keep running
            receive stop -> ok end;
        {error, Reason} ->
            io:format("Failed to start web server: ~p~n", [Reason]),
            halt(1)
    end;
execute_command(scan, #{cidrs := CIDRs, ports := Ports, opts := Opts}) ->
    io:format("Starting scan...~n"),
    io:format("CIDRs: ~p~n", [CIDRs]),
    io:format("Ports: ~p~n", [Ports]),
    
    %% Load exclude file if specified
    FinalOpts = case maps:get(exclude_file, Opts, undefined) of
        undefined ->
            %% Check for inline excludes
            case maps:get(excludes, Opts, []) of
                [] -> Opts;
                Excludes ->
                    ExcludeSet = lists:foldl(fun(E, Acc) ->
                        exclude_filter:add_cidr(E, Acc)
                    end, exclude_filter:new(), Excludes),
                    io:format("Excluding ~p CIDRs~n", [length(Excludes)]),
                    Opts#{exclude_set => ExcludeSet}
            end;
        ExcludeFile ->
            case exclude_filter:load(ExcludeFile) of
                {ok, ExcludeSet} ->
                    {IPCount, CIDRCount} = exclude_filter:count(ExcludeSet),
                    io:format("Loaded exclude file: ~p IPs, ~p CIDRs~n", [IPCount, CIDRCount]),
                    Opts#{exclude_set => ExcludeSet};
                {error, Reason} ->
                    io:format("Warning: Failed to load exclude file: ~p~n", [Reason]),
                    Opts
            end
    end,
    
    case massping_core:start_scan(CIDRs, Ports, FinalOpts) of
        {ok, ScanRef} ->
            io:format("Scan started: ~p~n", [ScanRef]),
            monitor_scan(ScanRef, FinalOpts),
            halt(0);
        {error, ScanError} ->
            io:format("Scan failed: ~p~n", [ScanError]),
            halt(1)
    end.

%% Monitor scan progress
monitor_scan(ScanRef, Opts) ->
    StartTime = erlang:monotonic_time(millisecond),
    monitor_loop(ScanRef, Opts, undefined, StartTime).

monitor_loop(ScanRef, Opts, LastProgress, StartTime) ->
    case massping_core:get_status(ScanRef) of
        {ok, Status} ->
            Progress = maps:get(progress, Status),
            State = maps:get(state, Status),
            Scanned = maps:get(scanned, Status),
            Total = maps:get(total, Status),
            
            %% Print progress if changed
            case Progress =/= LastProgress of
                true ->
                    print_progress(Status);
                false ->
                    ok
            end,
            
            %% Check if scan is complete (100% or stopped)
            case State =:= stopped orelse Scanned >= Total of
                true ->
                    %% Calculate elapsed time
                    EndTime = erlang:monotonic_time(millisecond),
                    ElapsedMs = EndTime - StartTime,
                    
                    %% Get results and save
                    {ok, Results} = massping_core:get_results(ScanRef),
                    print_results(Results, ElapsedMs),
                    
                    %% Save to file if requested
                    case maps:get(output, Opts, undefined) of
                        undefined -> ok;
                        Filename ->
                            Format = maps:get(format, Opts, json),
                            write_results(Filename, Results, Format)
                    end,
                    
                    io:format("~nScan complete!~n"),
                    ok;
                false ->
                    timer:sleep(500),
                    monitor_loop(ScanRef, Opts, Progress, StartTime)
            end;
        {error, _Reason} ->
            timer:sleep(500),
            monitor_loop(ScanRef, Opts, LastProgress, StartTime)
    end.

%% Print progress
print_progress(Status) ->
    Progress = maps:get(progress, Status),
    Scanned = maps:get(scanned, Status),
    Total = maps:get(total, Status),
    
    io:format("\rProgress: ~.2f% (~p/~p)", [Progress, Scanned, Total]).

%% Print results to stdout
print_results(Results, ElapsedMs) ->
    %% Categorize results
    OpenPorts = [{IP, Port} || {IP, {Status, Port}} <- Results, Status =:= open],
    ClosedPorts = [{IP, Port} || {IP, {Status, Port}} <- Results, Status =:= closed],
    FilteredPorts = [{IP, Port} || {IP, {Status, Port}} <- Results, Status =:= filtered],
    
    %% Group by IP for open ports
    OpenByIP = group_by_ip(OpenPorts),
    
    io:format("~n"),
    io:format("================================================================================~n"),
    io:format("                              MASSPING SCAN REPORT~n"),
    io:format("================================================================================~n"),
    io:format("~n"),
    
    %% Summary section
    io:format("SUMMARY~n"),
    io:format("--------------------------------------------------------------------------------~n"),
    io:format("  Total targets scanned:  ~p~n", [length(Results)]),
    io:format("  Open ports found:       ~p~n", [length(OpenPorts)]),
    io:format("  Closed ports:           ~p~n", [length(ClosedPorts)]),
    io:format("  Filtered ports:         ~p~n", [length(FilteredPorts)]),
    io:format("  Unique hosts with open: ~p~n", [length(OpenByIP)]),
    io:format("~n"),
    
    %% Open ports detail
    case OpenPorts of
        [] ->
            io:format("No open ports discovered.~n");
        _ ->
            io:format("OPEN PORTS~n"),
            io:format("--------------------------------------------------------------------------------~n"),
            io:format("  ~-18s ~-8s ~-15s~n", ["IP ADDRESS", "PORT", "SERVICE"]),
            io:format("--------------------------------------------------------------------------------~n"),
            lists:foreach(fun({IP, Port}) ->
                IPStr = cidr_parser:tuple_to_ip(IP),
                Service = port_to_service(Port),
                PortStr = integer_to_list(Port),
                io:format("  ~-18s ~-8s ~-15s~n", [IPStr, PortStr, Service])
            end, lists:sort(OpenPorts)),
            io:format("~n"),
            
            %% Grouped by host
            io:format("HOSTS WITH OPEN PORTS~n"),
            io:format("--------------------------------------------------------------------------------~n"),
            lists:foreach(fun({IP, Ports}) ->
                IPStr = cidr_parser:tuple_to_ip(IP),
                PortsStr = string:join([integer_to_list(P) ++ "/" ++ port_to_service(P) || P <- lists:sort(Ports)], ", "),
                io:format("  ~-18s ~s~n", [IPStr, PortsStr])
            end, lists:sort(OpenByIP)),
            io:format("~n"),
            
            %% Services summary
            ServiceCounts = count_services(OpenPorts),
            io:format("SERVICES DISCOVERED~n"),
            io:format("--------------------------------------------------------------------------------~n"),
            lists:foreach(fun({Service, Count}) ->
                io:format("  ~-20s ~p hosts~n", [Service, Count])
            end, lists:reverse(lists:keysort(2, ServiceCounts)))
    end,
    
    %% Timing section
    io:format("~n"),
    io:format("TIMING~n"),
    io:format("--------------------------------------------------------------------------------~n"),
    {Seconds, Ms} = {ElapsedMs div 1000, ElapsedMs rem 1000},
    {Minutes, Secs} = {Seconds div 60, Seconds rem 60},
    Rate = case ElapsedMs of
        0 -> 0;
        _ -> (length(Results) * 1000) div ElapsedMs
    end,
    io:format("  Total time:             ~pm ~ps ~pms~n", [Minutes, Secs, Ms]),
    io:format("  Scan rate:              ~p targets/sec~n", [Rate]),
    io:format("~n"),
    io:format("================================================================================~n"),
    io:format("~n").

%% Group ports by IP
group_by_ip(PortList) ->
    Dict = lists:foldl(fun({IP, Port}, Acc) ->
        case lists:keyfind(IP, 1, Acc) of
            {IP, Ports} ->
                lists:keyreplace(IP, 1, Acc, {IP, [Port | Ports]});
            false ->
                [{IP, [Port]} | Acc]
        end
    end, [], PortList),
    Dict.

%% Count services
count_services(PortList) ->
    Counts = lists:foldl(fun({_IP, Port}, Acc) ->
        Service = port_to_service(Port),
        case lists:keyfind(Service, 1, Acc) of
            {Service, Count} ->
                lists:keyreplace(Service, 1, Acc, {Service, Count + 1});
            false ->
                [{Service, 1} | Acc]
        end
    end, [], PortList),
    Counts.

%% Write results to file
write_results(Filename, Results, json) ->
    JSON = format_json(Results),
    file:write_file(Filename, JSON),
    io:format("Results saved to ~s~n", [Filename]);
write_results(Filename, Results, csv) ->
    CSV = format_csv(Results),
    file:write_file(Filename, CSV),
    io:format("Results saved to ~s~n", [Filename]);
write_results(Filename, Results, xml) ->
    XML = format_xml(Results),
    file:write_file(Filename, XML),
    io:format("Results saved to ~s~n", [Filename]);
write_results(Filename, Results, grepable) ->
    Grepable = format_grepable(Results),
    file:write_file(Filename, Grepable),
    io:format("Results saved to ~s~n", [Filename]);
write_results(Filename, Results, _Unknown) ->
    %% Default to JSON
    write_results(Filename, Results, json).

%% Format results as JSON
format_json(Results) ->
    Formatted = lists:map(fun({IP, {Status, Port}}) ->
        IPStr = cidr_parser:tuple_to_ip(IP),
        io_lib:format("{\"ip\":\"~s\",\"port\":~p,\"status\":\"~s\",\"service\":\"~s\"}", 
                      [IPStr, Port, Status, port_to_service(Port)])
    end, Results),
    ["[\n", string:join(Formatted, ",\n"), "\n]"].

%% Format results as CSV
format_csv(Results) ->
    Header = "ip,port,status,service\n",
    Lines = lists:map(fun({IP, {Status, Port}}) ->
        IPStr = cidr_parser:tuple_to_ip(IP),
        Service = port_to_service(Port),
        io_lib:format("~s,~p,~s,~s~n", [IPStr, Port, Status, Service])
    end, Results),
    [Header | Lines].

%% Format results as XML (nmap-style)
format_xml(Results) ->
    %% Group results by IP
    ByIP = group_results_by_ip(Results),
    
    Header = [
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<!DOCTYPE massping>\n",
        "<massping scanner=\"massping\" version=\"1.0.0\" ",
        "start=\"", integer_to_list(erlang:system_time(second)), "\">\n"
    ],
    
    Hosts = lists:map(fun({IP, PortResults}) ->
        IPStr = cidr_parser:tuple_to_ip(IP),
        OpenPorts = [{P, S} || {S, P} <- PortResults, S =:= open],
        ClosedPorts = [{P, S} || {S, P} <- PortResults, S =:= closed],
        FilteredPorts = [{P, S} || {S, P} <- PortResults, S =:= filtered],
        
        HostStatus = case length(OpenPorts) > 0 of
            true -> "up";
            false -> "down"
        end,
        
        PortLines = lists:map(fun({Port, Status}) ->
            Service = port_to_service(Port),
            io_lib:format("      <port protocol=\"tcp\" portid=\"~p\">\n"
                          "        <state state=\"~s\"/>\n"
                          "        <service name=\"~s\"/>\n"
                          "      </port>\n", [Port, Status, Service])
        end, OpenPorts ++ ClosedPorts ++ FilteredPorts),
        
        [
            "  <host>\n",
            "    <status state=\"", HostStatus, "\"/>\n",
            "    <address addr=\"", IPStr, "\" addrtype=\"ipv4\"/>\n",
            "    <ports>\n",
            PortLines,
            "    </ports>\n",
            "  </host>\n"
        ]
    end, ByIP),
    
    Footer = "</massping>\n",
    [Header, Hosts, Footer].

%% Format results as grepable (nmap -oG style)
format_grepable(Results) ->
    %% Group results by IP
    ByIP = group_results_by_ip(Results),
    
    Header = io_lib:format("# Massping grepable output - ~s~n", 
                           [format_timestamp()]),
    
    Lines = lists:map(fun({IP, PortResults}) ->
        IPStr = cidr_parser:tuple_to_ip(IP),
        OpenPorts = [P || {S, P} <- PortResults, S =:= open],
        
        case OpenPorts of
            [] ->
                io_lib:format("Host: ~s ()\tStatus: Down~n", [IPStr]);
            _ ->
                PortStr = string:join(
                    [io_lib:format("~p/open/tcp//~s//", [P, port_to_service(P)]) 
                     || P <- lists:sort(OpenPorts)], 
                    ", "),
                io_lib:format("Host: ~s ()\tStatus: Up\tPorts: ~s~n", 
                              [IPStr, PortStr])
        end
    end, ByIP),
    
    [Header | Lines].

%% Group results by IP
group_results_by_ip(Results) ->
    Dict = lists:foldl(fun({IP, PortResult}, Acc) ->
        case maps:get(IP, Acc, undefined) of
            undefined ->
                maps:put(IP, [PortResult], Acc);
            Existing ->
                maps:put(IP, [PortResult | Existing], Acc)
        end
    end, #{}, Results),
    maps:to_list(Dict).

%% Format current timestamp
format_timestamp() ->
    {{Y, M, D}, {H, Mi, S}} = calendar:local_time(),
    io_lib:format("~4..0B-~2..0B-~2..0B ~2..0B:~2..0B:~2..0B", 
                  [Y, M, D, H, Mi, S]).

%% Map port to service name
port_to_service(21) -> "FTP";
port_to_service(22) -> "SSH";
port_to_service(23) -> "Telnet";
port_to_service(25) -> "SMTP";
port_to_service(53) -> "DNS";
port_to_service(80) -> "HTTP";
port_to_service(110) -> "POP3";
port_to_service(143) -> "IMAP";
port_to_service(443) -> "HTTPS";
port_to_service(445) -> "SMB";
port_to_service(993) -> "IMAPS";
port_to_service(995) -> "POP3S";
port_to_service(1433) -> "MSSQL";
port_to_service(1521) -> "Oracle";
port_to_service(3306) -> "MySQL";
port_to_service(3389) -> "RDP";
port_to_service(5432) -> "PostgreSQL";
port_to_service(5900) -> "VNC";
port_to_service(6379) -> "Redis";
port_to_service(8080) -> "HTTP-Proxy";
port_to_service(8443) -> "HTTPS-Alt";
port_to_service(27017) -> "MongoDB";
port_to_service(_) -> "Unknown".

%% Print error message
print_error(no_command) ->
    io:format("Error: No command specified~n");
print_error({unknown_command, Cmd}) ->
    io:format("Error: Unknown command '~s'~n", [Cmd]);
print_error(no_cidrs_specified) ->
    io:format("Error: No CIDR ranges specified~n");
print_error(no_ports_specified) ->
    io:format("Error: No ports specified~n");
print_error(invalid_arguments) ->
    io:format("Error: Invalid arguments~n");
print_error(Reason) ->
    io:format("Error: ~p~n", [Reason]).

%% Print usage information
print_usage() ->
    io:format("~n"),
    io:format("================================================================================~n"),
    io:format("  MassPing v1.0.0 - High-performance distributed port scanner~n"),
    io:format("================================================================================~n~n"),
    io:format("USAGE:~n"),
    io:format("  massping scan <CIDR> [options]~n"),
    io:format("  massping web [options]~n"),
    io:format("  massping sessions~n"),
    io:format("  massping resume <session-id>~n"),
    io:format("  massping help~n~n"),
    io:format("OPTIONS:~n"),
    io:format("  -p, --ports <ports>       Comma-separated list of ports~n"),
    io:format("                            Example: -p 22,80,443,8080~n~n"),
    io:format("  -t, --timeout <ms>        Connection timeout in milliseconds~n"),
    io:format("                            Default: 1000 (1 second)~n"),
    io:format("                            Note: SSH/Telnet/RDP auto-adjust to min 3000ms~n~n"),
    io:format("  -c, --concurrency <num>   Max concurrent connections~n"),
    io:format("                            Default: 5000~n"),
    io:format("                            Higher = faster but may lose results~n~n"),
    io:format("  -r, --retries <num>       Retry count for filtered ports~n"),
    io:format("                            Default: 0 (disabled for speed)~n"),
    io:format("                            Use -r 3 for accuracy~n~n"),
    io:format("  --rate <rps>              Rate limit (requests per second)~n"),
    io:format("                            Default: unlimited~n~n"),
    io:format("  -o, --output <file>       Save results to file~n"),
    io:format("  --format <format>         Output format: json, csv, xml, grepable~n"),
    io:format("                            Default: json~n~n"),
    io:format("SCAN MODES:~n"),
    io:format("  --aggressive              Fast and reliable (recommended)~n"),
    io:format("                            8K concurrency, 1.5s timeout, 3 retries~n~n"),
    io:format("  --ultra                   Maximum speed (may miss slow hosts)~n"),
    io:format("                            15K concurrency, 800ms timeout, 2 retries~n~n"),
    io:format("  --turbo                   Insane speed for LAN only~n"),
    io:format("                            25K concurrency, 300ms timeout, 1 retry~n~n"),
    io:format("  --stealth                 Slow and stealthy (avoids detection)~n"),
    io:format("                            500 concurrency, 5s timeout, randomized~n~n"),
    io:format("SCAN TYPES:~n"),
    io:format("  --syn                     SYN scan - fast half-open (requires root)~n"),
    io:format("  --no-syn                  TCP connect scan (default)~n"),
    io:format("  --udp                     UDP scan for services (DNS, SNMP, NTP)~n~n"),
    io:format("SERVICE DETECTION:~n"),
    io:format("  --grab-banner             Grab service banners~n"),
    io:format("  --detect-service          Enhanced service/version detection~n~n"),
    io:format("EXCLUDE OPTIONS:~n"),
    io:format("  --exclude-file <file>     File with IPs/CIDRs to exclude~n"),
    io:format("  --exclude <cidr>          Inline exclude (can repeat)~n~n"),
    io:format("SESSION MANAGEMENT:~n"),
    io:format("  --session <id>            Save scan progress to session~n"),
    io:format("  --resume <id>             Resume scan from saved session~n"),
    io:format("  --list-sessions           List all saved sessions~n~n"),
    io:format("WEB SERVER:~n"),
    io:format("  --web                     Start web UI server~n"),
    io:format("  --web-port <port>         Web server port (default: 8080)~n~n"),
    io:format("ADVANCED OPTIONS:~n"),
    io:format("  --randomize               Randomize target order (IDS evasion)~n"),
    io:format("  --filter-blackhole        Skip unroutable IPs~n"),
    io:format("  --adaptive                Enable AIMD adaptive rate control~n"),
    io:format("  --batch-size <num>        Batch size for SYN scan (default: 1000)~n"),
    io:format("  --chunks <num>            Chunk multiplier (default: 2 x CPUs)~n~n"),
    io:format("EXAMPLES:~n"),
    io:format("  # Simple scan~n"),
    io:format("  massping scan 192.168.1.0/24 -p 80,443,22~n~n"),
    io:format("  # Fast aggressive scan~n"),
    io:format("  massping scan 10.0.0.0/16 -p 80,443 --aggressive~n~n"),
    io:format("  # SYN scan with service detection~n"),
    io:format("  sudo massping scan 10.0.0.0/8 -p 80,443 --syn --detect-service~n~n"),
    io:format("  # UDP scan for DNS and SNMP~n"),
    io:format("  massping scan 192.168.0.0/16 -p 53,161 --udp~n~n"),
    io:format("  # Scan with excludes~n"),
    io:format("  massping scan 10.0.0.0/8 -p 80 --exclude-file excludes.txt~n~n"),
    io:format("  # Save session for resume~n"),
    io:format("  massping scan 10.0.0.0/8 -p 80 --session my-scan~n~n"),
    io:format("  # Resume interrupted scan~n"),
    io:format("  massping resume my-scan~n~n"),
    io:format("  # Start web UI~n"),
    io:format("  massping --web --web-port 8888~n~n"),
    io:format("  # Export to different formats~n"),
    io:format("  massping scan 10.0.0.0/24 -p 80 --format xml -o scan.xml~n"),
    io:format("  massping scan 10.0.0.0/24 -p 80 --format grepable -o scan.grep~n~n"),
    io:format("SYSTEM TUNING (macOS):~n"),
    io:format("  ulimit -n 50000~n"),
    io:format("  sudo sysctl -w kern.maxfilesperproc=50000~n~n"),
    io:format("LEGAL NOTICE:~n"),
    io:format("  Only scan networks you own or have explicit permission to scan.~n"),
    io:format("================================================================================~n~n").

%%====================================================================
%% Tests
%%====================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

parse_ports_test() ->
    ?assertEqual([80, 443, 22], parse_ports("80,443,22")),
    ?assertEqual([8080], parse_ports("8080")).

-endif.
