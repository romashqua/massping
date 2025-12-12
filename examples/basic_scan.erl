#!/usr/bin/env escript
%%! -pa _build/default/lib/massping/ebin

%%%-------------------------------------------------------------------
%%% @doc Example: Basic scanning
%%%-------------------------------------------------------------------

main(_Args) ->
    %% Ensure application is started
    application:ensure_all_started(massping),
    
    io:format("=== MassPing Basic Scan Example ===~n~n"),
    
    %% Example 1: Scan single subnet
    io:format("Example 1: Scanning 192.168.1.0/24 for common ports~n"),
    {ok, ScanRef1} = massping:scan("192.168.1.0/24", [80, 443, 22]),
    
    timer:sleep(2000),
    {ok, Status1} = massping:status(ScanRef1),
    io:format("Status: ~p~n", [Status1]),
    
    %% Example 2: Scan with custom options
    io:format("~nExample 2: Fast scan with high rate limit~n"),
    {ok, ScanRef2} = massping:scan(
        "192.168.1.0/24",
        [80, 443],
        #{
            rate_limit => 50000,
            timeout => 500
        }
    ),
    
    timer:sleep(2000),
    {ok, Status2} = massping:status(ScanRef2),
    io:format("Status: ~p~n", [Status2]),
    
    %% Example 3: Multiple subnets
    io:format("~nExample 3: Scanning multiple subnets~n"),
    {ok, ScanRef3} = massping:scan(
        ["192.168.1.0/24", "192.168.2.0/24"],
        [80, 443, 8080],
        #{rate_limit => 20000}
    ),
    
    timer:sleep(2000),
    {ok, Status3} = massping:status(ScanRef3),
    io:format("Status: ~p~n", [Status3]),
    
    io:format("~nAll examples started successfully!~n"),
    timer:sleep(5000),
    halt(0).
