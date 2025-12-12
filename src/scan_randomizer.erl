%%%-------------------------------------------------------------------
%%% @doc IP/Port randomization for stealthy scanning
%%% Uses multiplicative LCG for pseudo-random permutation without
%%% storing the entire list in memory
%%% 
%%% Based on techniques from masscan/zmap for evading detection
%%% @end
%%%-------------------------------------------------------------------
-module(scan_randomizer).

-export([
    shuffle/1,
    shuffle_stream/2,
    blackhole_filter/1,
    is_scannable/1
]).

%% Blacklisted ranges (RFC 5735, RFC 1918, etc.)
-define(BLACKLIST, [
    {{0, 0, 0, 0}, 8},        % 0.0.0.0/8 - Current network
    {{10, 0, 0, 0}, 8},       % 10.0.0.0/8 - Private (skip by default)
    {{100, 64, 0, 0}, 10},    % 100.64.0.0/10 - Carrier-grade NAT
    {{127, 0, 0, 0}, 8},      % 127.0.0.0/8 - Loopback
    {{169, 254, 0, 0}, 16},   % 169.254.0.0/16 - Link-local
    {{172, 16, 0, 0}, 12},    % 172.16.0.0/12 - Private
    {{192, 0, 0, 0}, 24},     % 192.0.0.0/24 - IETF Protocol
    {{192, 0, 2, 0}, 24},     % 192.0.2.0/24 - TEST-NET-1
    {{192, 88, 99, 0}, 24},   % 192.88.99.0/24 - 6to4 Relay
    {{192, 168, 0, 0}, 16},   % 192.168.0.0/16 - Private
    {{198, 18, 0, 0}, 15},    % 198.18.0.0/15 - Benchmark
    {{198, 51, 100, 0}, 24},  % 198.51.100.0/24 - TEST-NET-2
    {{203, 0, 113, 0}, 24},   % 203.0.113.0/24 - TEST-NET-3
    {{224, 0, 0, 0}, 4},      % 224.0.0.0/4 - Multicast
    {{240, 0, 0, 0}, 4},      % 240.0.0.0/4 - Reserved
    {{255, 255, 255, 255}, 32} % Broadcast
]).

%%====================================================================
%% API
%%====================================================================

%% @doc Shuffle a list of targets using Fisher-Yates
%% For smaller lists (< 100K targets)
-spec shuffle([{tuple(), integer()}]) -> [{tuple(), integer()}].
shuffle(List) ->
    %% Seed random with current time for uniqueness
    rand:seed(exsss, {erlang:monotonic_time(), erlang:unique_integer(), erlang:phash2(self())}),
    shuffle_internal(List, []).

shuffle_internal([], Acc) -> Acc;
shuffle_internal(List, Acc) ->
    {Leading, [H | T]} = lists:split(rand:uniform(length(List)) - 1, List),
    shuffle_internal(Leading ++ T, [H | Acc]).

%% @doc Create a randomized stream using LCG permutation
%% Memory-efficient for large scans (millions of targets)
%% Based on: https://lemire.me/blog/2017/09/18/visiting-all-values-in-an-array-exactly-once/
-spec shuffle_stream([{tuple(), integer()}], pos_integer()) -> 
    fun(() -> {tuple(), integer()} | done).
shuffle_stream(Targets, Seed) ->
    N = length(Targets),
    TargetArray = array:from_list(Targets),
    
    %% Find next power of 2 >= N
    P = next_power_of_2(N),
    
    %% LCG parameters (must be coprime with P)
    A = 5,  % Multiplier
    C = 1,  % Increment (odd for power of 2)
    
    %% Start with seed
    StartIdx = Seed rem P,
    
    make_lcg_stream(TargetArray, N, P, A, C, StartIdx, 0).

%% @doc Filter out blackholed/non-scannable IPs
-spec blackhole_filter([{tuple(), integer()}]) -> [{tuple(), integer()}].
blackhole_filter(Targets) ->
    [T || T = {IP, _Port} <- Targets, is_scannable(IP)].

%% @doc Check if IP is scannable (not in blacklist)
-spec is_scannable(tuple()) -> boolean().
is_scannable(IP) ->
    not lists:any(fun({Network, Mask}) ->
        ip_in_range(IP, Network, Mask)
    end, ?BLACKLIST).

%%====================================================================
%% Internal functions
%%====================================================================

%% Check if IP is within a CIDR range
ip_in_range({A, B, C, D}, {NA, NB, NC, ND}, Mask) ->
    IPInt = (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D,
    NetworkInt = (NA bsl 24) bor (NB bsl 16) bor (NC bsl 8) bor ND,
    MaskBits = (16#FFFFFFFF bsl (32 - Mask)) band 16#FFFFFFFF,
    (IPInt band MaskBits) =:= (NetworkInt band MaskBits).

%% Find next power of 2 >= N
next_power_of_2(N) ->
    next_power_of_2(N, 1).

next_power_of_2(N, P) when P >= N -> P;
next_power_of_2(N, P) -> next_power_of_2(N, P * 2).

%% Create LCG-based stream
make_lcg_stream(_Array, _N, _P, _A, _C, _Idx, Count) when Count >= 1000000 ->
    %% Safety limit
    fun() -> done end;
make_lcg_stream(Array, N, P, A, C, Idx, Count) ->
    fun() ->
        %% Find next valid index using LCG
        find_next_valid(Array, N, P, A, C, Idx, Count)
    end.

find_next_valid(_Array, N, _P, _A, _C, _Idx, Count) when Count >= N ->
    done;
find_next_valid(Array, N, P, A, C, Idx, Count) ->
    NextIdx = ((A * Idx + C) rem P),
    if
        Idx < N ->
            Target = array:get(Idx, Array),
            {Target, make_lcg_stream(Array, N, P, A, C, NextIdx, Count + 1)};
        true ->
            %% Skip indices >= N, try next
            find_next_valid(Array, N, P, A, C, NextIdx, Count)
    end.

%%====================================================================
%% Tests
%%====================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

blacklist_test() ->
    ?assertEqual(false, is_scannable({127, 0, 0, 1})),
    ?assertEqual(false, is_scannable({10, 0, 0, 1})),
    ?assertEqual(false, is_scannable({192, 168, 1, 1})),
    ?assertEqual(false, is_scannable({224, 0, 0, 1})),
    ?assertEqual(true, is_scannable({8, 8, 8, 8})),
    ?assertEqual(true, is_scannable({1, 1, 1, 1})).

shuffle_test() ->
    List = [{1,80}, {2,80}, {3,80}, {4,80}, {5,80}],
    Shuffled = shuffle(List),
    ?assertEqual(5, length(Shuffled)),
    ?assertEqual(lists:sort(List), lists:sort(Shuffled)).

filter_test() ->
    Targets = [
        {{8, 8, 8, 8}, 80},      % Valid
        {{127, 0, 0, 1}, 80},    % Loopback - filtered
        {{192, 168, 1, 1}, 80},  % Private - filtered
        {{1, 1, 1, 1}, 443}      % Valid
    ],
    Filtered = blackhole_filter(Targets),
    ?assertEqual(2, length(Filtered)).

-endif.
