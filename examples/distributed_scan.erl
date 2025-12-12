#!/usr/bin/env escript
%%! -pa _build/default/lib/massping/ebin

%%%-------------------------------------------------------------------
%%% @doc Example: Distributed scanning across cluster
%%%-------------------------------------------------------------------

main(_Args) ->
    application:ensure_all_started(massping),
    
    io:format("=== MassPing Distributed Scan Example ===~n~n"),
    
    %% Start distributed Erlang
    net_kernel:start(['master@127.0.0.1', longnames]),
    erlang:set_cookie(node(), massping_cluster),
    
    %% Add cluster nodes
    io:format("Setting up cluster...~n"),
    Nodes = ['node1@192.168.1.10', 'node2@192.168.1.11'],
    
    lists:foreach(fun(Node) ->
        case massping_dist:add_node(Node) of
            ok -> io:format("  Added node: ~p~n", [Node]);
            {error, Reason} -> io:format("  Failed to add ~p: ~p~n", [Node, Reason])
        end
    end, Nodes),
    
    %% Get cluster status
    Status = massping_dist:get_cluster_status(),
    io:format("~nCluster status: ~p~n", [Status]),
    
    %% Perform distributed scan
    io:format("~nStarting distributed scan...~n"),
    CIDRs = [
        "10.0.0.0/16",
        "192.168.0.0/16"
    ],
    
    {ok, ScanRef, Results} = massping_dist:scan_cluster(
        CIDRs,
        [80, 443, 22],
        #{
            rate_per_node => 10000,
            distribution_strategy => round_robin
        }
    ),
    
    io:format("Scan started with ref: ~p~n", [ScanRef]),
    io:format("Node results: ~p~n", [Results]),
    
    %% Wait for results
    timer:sleep(10000),
    
    {ok, FinalResults} = massping_dist:collect_results(ScanRef),
    io:format("~nTotal results collected: ~p~n", [length(FinalResults)]),
    
    halt(0).
