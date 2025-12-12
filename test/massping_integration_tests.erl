%%%-------------------------------------------------------------------
%%% @doc Integration tests for MassPing
%%% @end
%%%-------------------------------------------------------------------
-module(massping_integration_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Setup/Teardown
%%====================================================================

setup() ->
    application:ensure_all_started(massping),
    ok.

teardown(_) ->
    application:stop(massping),
    ok.

%%====================================================================
%% Tests
%%====================================================================

basic_scan_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun(_) ->
         [{"scan loopback",
           fun() ->
               %% Test scanning local loopback
               {ok, ScanRef} = massping:scan("127.0.0.1/32", [22, 80, 443]),
               
               %% Wait a bit
               timer:sleep(2000),
               
               %% Check status
               {ok, Status} = massping:status(ScanRef),
               ?assert(maps:is_key(state, Status)),
               ?assert(maps:is_key(total, Status)),
               
               %% Get results
               {ok, Results} = massping:results(ScanRef),
               ?assert(is_list(Results))
           end}]
     end}.

rate_limiter_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun(_) ->
         [{"rate limiter",
           fun() ->
               %% Test rate limiting
               {ok, Limiter} = rate_limiter:start_link(100),
               
               %% Should be able to acquire immediately
               ?assertEqual(ok, rate_limiter:acquire(Limiter)),
               
               %% Get stats
               Stats = rate_limiter:get_stats(Limiter),
               ?assert(maps:get(granted, Stats) > 0),
               
               rate_limiter:stop(Limiter)
           end}]
     end}.

cidr_parser_test_() ->
    [
        ?_assertEqual(256, cidr_parser:count_ips("192.168.1.0/24")),
        ?_assertEqual(65536, cidr_parser:count_ips("10.0.0.0/16")),
        ?_assertEqual(1, cidr_parser:count_ips("192.168.1.1/32")),
        
        ?_assertEqual({192, 168, 1, 1}, cidr_parser:ip_to_tuple("192.168.1.1")),
        ?_assertEqual("192.168.1.1", cidr_parser:tuple_to_ip({192, 168, 1, 1}))
    ].

stream_parsing_test_() ->
    {setup,
     fun() -> ok end,
     fun(_) -> ok end,
     fun(_) ->
         [{"stream parsing",
           fun() ->
               %% Test stream parsing for memory efficiency
               Stream = cidr_parser:parse_stream("192.168.1.0/30"),
               
               %% Should be able to get IPs one by one
               {IP1, Stream2} = Stream(),
               ?assertEqual({192, 168, 1, 0}, IP1),
               
               {IP2, Stream3} = Stream2(),
               ?assertEqual({192, 168, 1, 1}, IP2),
               
               {IP3, Stream4} = Stream3(),
               ?assertEqual({192, 168, 1, 2}, IP3),
               
               {IP4, Stream5} = Stream4(),
               ?assertEqual({192, 168, 1, 3}, IP4),
               
               ?assertEqual(done, Stream5())
           end}]
     end}.

multiple_scans_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun(_) ->
         [{"multiple concurrent scans",
           fun() ->
               %% Test multiple concurrent scans
               {ok, Scan1} = massping:scan("127.0.0.1/32", [22]),
               {ok, Scan2} = massping:scan("127.0.0.1/32", [80]),
               
               timer:sleep(1000),
               
               {ok, Status1} = massping:status(Scan1),
               {ok, Status2} = massping:status(Scan2),
               
               ?assert(maps:is_key(state, Status1)),
               ?assert(maps:is_key(state, Status2))
           end}]
     end}.

%%====================================================================
%% Performance Tests
%%====================================================================

performance_small_network_test_() ->
    {timeout, 60,
     {setup,
      fun setup/0,
      fun teardown/1,
      fun(_) ->
          [{"small network performance",
            fun() ->
                %% Scan small network and measure time
                StartTime = erlang:monotonic_time(millisecond),
                
                {ok, ScanRef} = massping:scan("192.168.1.0/28", [80, 443], #{
                    rate_limit => 10000
                }),
                
                %% Wait for completion
                wait_for_scan(ScanRef, 30000),
                
                EndTime = erlang:monotonic_time(millisecond),
                Duration = EndTime - StartTime,
                
                io:format("~nSmall network scan took ~p ms~n", [Duration]),
                
                %% Should complete reasonably fast
                ?assert(Duration < 30000)
            end}]
      end}}.

%%====================================================================
%% Helper Functions
%%====================================================================

wait_for_scan(ScanRef, Timeout) when Timeout > 0 ->
    case massping:status(ScanRef) of
        {ok, #{state := stopped}} ->
            ok;
        {ok, #{state := completed}} ->
            ok;
        {ok, #{state := running}} ->
            timer:sleep(500),
            wait_for_scan(ScanRef, Timeout - 500);
        {ok, #{state := pending}} ->
            timer:sleep(100),
            wait_for_scan(ScanRef, Timeout - 100);
        {error, _} ->
            timeout
    end;
wait_for_scan(_, _) ->
    timeout.
