%%%-------------------------------------------------------------------
%%% @doc Distributed scanning module for MassPing
%%% Enables cluster-based scanning across multiple Erlang nodes
%%% @end
%%%-------------------------------------------------------------------
-module(massping_dist).

-export([
    scan_cluster/3,
    add_node/1,
    remove_node/1,
    get_cluster_nodes/0,
    get_cluster_status/0,
    collect_results/1
]).

-type distribution_strategy() :: round_robin | hash_based | least_loaded.

%%====================================================================
%% API
%%====================================================================

%% @doc Scan across multiple nodes in cluster
-spec scan_cluster([string()], [pos_integer()], map()) ->
    {ok, reference(), [node()]} | {error, term()}.
scan_cluster(CIDRs, Ports, Opts) ->
    Nodes = case maps:get(nodes, Opts, undefined) of
        undefined -> get_cluster_nodes();
        NodeList -> NodeList
    end,
    
    case Nodes of
        [] ->
            {error, no_nodes_available};
        _ ->
            Strategy = maps:get(distribution_strategy, Opts, round_robin),
            RatePerNode = maps:get(rate_per_node, Opts, 5000),
            
            %% Distribute work across nodes
            WorkDistribution = distribute_work(CIDRs, Ports, Nodes, Strategy),
            
            %% Start scanning on each node
            ScanRef = make_ref(),
            Results = start_distributed_scan(WorkDistribution, RatePerNode, Opts, ScanRef),
            
            {ok, ScanRef, Results}
    end.

%% @doc Add a node to the cluster
-spec add_node(node()) -> ok | {error, term()}.
add_node(Node) ->
    case net_adm:ping(Node) of
        pong ->
            io:format("Node ~p joined cluster~n", [Node]),
            ok;
        pang ->
            {error, node_unreachable}
    end.

%% @doc Remove a node from cluster
-spec remove_node(node()) -> ok.
remove_node(Node) ->
    erlang:disconnect_node(Node),
    ok.

%% @doc Get list of available cluster nodes
-spec get_cluster_nodes() -> [node()].
get_cluster_nodes() ->
    [node() | nodes()].

%% @doc Get cluster status including load information
-spec get_cluster_status() -> map().
get_cluster_status() ->
    Nodes = get_cluster_nodes(),
    
    NodeStats = lists:map(fun(Node) ->
        case rpc:call(Node, erlang, statistics, [scheduler_wall_time]) of
            {badrpc, Reason} ->
                #{node => Node, status => {error, Reason}};
            Stats ->
                #{
                    node => Node,
                    status => ok,
                    schedulers => length(Stats),
                    memory => rpc:call(Node, erlang, memory, [total])
                }
        end
    end, Nodes),
    
    #{
        total_nodes => length(Nodes),
        nodes => NodeStats
    }.

%% @doc Collect results from distributed scan
-spec collect_results(reference()) -> {ok, [term()]} | {error, term()}.
collect_results(ScanRef) ->
    collect_results_loop(ScanRef, [], 5000).

%%====================================================================
%% Internal functions
%%====================================================================

%% Distribute work across nodes based on strategy
-spec distribute_work([string()], [pos_integer()], [node()], distribution_strategy()) ->
    [{node(), [string()], [pos_integer()]}].
distribute_work(CIDRs, Ports, Nodes, Strategy) ->
    case Strategy of
        round_robin ->
            distribute_round_robin(CIDRs, Ports, Nodes);
        hash_based ->
            distribute_hash_based(CIDRs, Ports, Nodes);
        least_loaded ->
            distribute_least_loaded(CIDRs, Ports, Nodes)
    end.

%% Round-robin distribution
distribute_round_robin(CIDRs, Ports, Nodes) ->
    NodeCount = length(Nodes),
    IndexedCIDRs = lists:zip(lists:seq(0, length(CIDRs) - 1), CIDRs),
    
    %% Group CIDRs by node
    Grouped = lists:foldl(fun({Idx, CIDR}, Acc) ->
        Node = lists:nth((Idx rem NodeCount) + 1, Nodes),
        maps:update_with(Node, fun(List) -> [CIDR | List] end, [CIDR], Acc)
    end, #{}, IndexedCIDRs),
    
    %% Convert to list format
    [{Node, lists:reverse(NodeCIDRs), Ports} || {Node, NodeCIDRs} <- maps:to_list(Grouped)].

%% Hash-based distribution (consistent hashing)
distribute_hash_based(CIDRs, Ports, Nodes) ->
    Grouped = lists:foldl(fun(CIDR, Acc) ->
        Hash = erlang:phash2(CIDR, length(Nodes)),
        Node = lists:nth(Hash + 1, Nodes),
        maps:update_with(Node, fun(List) -> [CIDR | List] end, [CIDR], Acc)
    end, #{}, CIDRs),
    
    [{Node, lists:reverse(NodeCIDRs), Ports} || {Node, NodeCIDRs} <- maps:to_list(Grouped)].

%% Least-loaded distribution
distribute_least_loaded(CIDRs, Ports, Nodes) ->
    %% Get load information for each node
    NodeLoads = lists:map(fun(Node) ->
        case rpc:call(Node, erlang, statistics, [total_active_tasks]) of
            {badrpc, _} -> {Node, 999999};
            Load -> {Node, Load}
        end
    end, Nodes),
    
    SortedNodes = [N || {N, _} <- lists:keysort(2, NodeLoads)],
    
    %% Distribute based on sorted load
    distribute_round_robin(CIDRs, Ports, SortedNodes).

%% Start scanning on distributed nodes
start_distributed_scan(WorkDistribution, RatePerNode, Opts, _ScanRef) ->
    lists:map(fun({Node, CIDRs, Ports}) ->
        NodeOpts = Opts#{rate_limit => RatePerNode},
        
        case rpc:call(Node, massping_core, start_scan, [CIDRs, Ports, NodeOpts]) of
            {ok, LocalScanRef} ->
                {Node, ok, LocalScanRef};
            {error, Reason} ->
                io:format("Failed to start scan on ~p: ~p~n", [Node, Reason]),
                {Node, error, Reason};
            {badrpc, Reason} ->
                io:format("RPC error on ~p: ~p~n", [Node, Reason]),
                {Node, error, Reason}
        end
    end, WorkDistribution).

%% Collect results from all nodes
collect_results_loop(_ScanRef, Results, Timeout) when Timeout =< 0 ->
    {ok, Results};
collect_results_loop(ScanRef, Results, Timeout) ->
    StartTime = erlang:monotonic_time(millisecond),
    
    receive
        {scan_complete, ScanRef, NodeResults} ->
            NewResults = NodeResults ++ Results,
            Elapsed = erlang:monotonic_time(millisecond) - StartTime,
            collect_results_loop(ScanRef, NewResults, Timeout - Elapsed);
        {scan_error, ScanRef, Error} ->
            io:format("Scan error: ~p~n", [Error]),
            Elapsed = erlang:monotonic_time(millisecond) - StartTime,
            collect_results_loop(ScanRef, Results, Timeout - Elapsed)
    after Timeout ->
        {ok, Results}
    end.

%%====================================================================
%% Tests
%%====================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

distribute_round_robin_test() ->
    CIDRs = ["192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"],
    Ports = [80, 443],
    Nodes = [node1@host, node2@host],
    
    Result = distribute_round_robin(CIDRs, Ports, Nodes),
    ?assertEqual(2, length(Result)).

distribute_hash_based_test() ->
    CIDRs = ["192.168.1.0/24", "192.168.2.0/24"],
    Ports = [80],
    Nodes = [node1@host, node2@host],
    
    Result = distribute_hash_based(CIDRs, Ports, Nodes),
    ?assert(length(Result) > 0).

-endif.
