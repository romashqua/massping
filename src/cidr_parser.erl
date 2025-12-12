%%%-------------------------------------------------------------------
%%% @doc CIDR parser with stream processing for large IP ranges
%%% Supports conversion of CIDR notation to IP addresses without
%%% loading entire range into memory
%%% @end
%%%-------------------------------------------------------------------
-module(cidr_parser).

-export([
    parse/1,
    parse_stream/1,
    range_to_ips/1,
    ip_to_tuple/1,
    tuple_to_ip/1,
    count_ips/1,
    chunk_range/2
]).

-type ip_address() :: {byte(), byte(), byte(), byte()}.
-type cidr() :: string().
-type ip_range() :: {ip_address(), ip_address()}.

%%====================================================================
%% API
%%====================================================================

%% @doc Parse CIDR notation and return list of IPs
%% For small ranges only. Use parse_stream/1 for large ranges.
-spec parse(cidr()) -> [ip_address()].
parse(CIDR) ->
    {StartIP, EndIP} = parse_cidr(CIDR),
    range_to_list(StartIP, EndIP).

%% @doc Parse CIDR notation and return stream function
%% Memory-efficient for large ranges
-spec parse_stream(cidr()) -> fun(() -> ip_address() | done).
parse_stream(CIDR) ->
    {StartIP, EndIP} = parse_cidr(CIDR),
    Current = ip_to_integer(StartIP),
    End = ip_to_integer(EndIP),
    make_stream(Current, End).

%% @doc Convert IP range to list of IPs
-spec range_to_ips(ip_range()) -> [ip_address()].
range_to_ips({StartIP, EndIP}) ->
    range_to_list(StartIP, EndIP).

%% @doc Convert IP string to tuple
-spec ip_to_tuple(string()) -> ip_address().
ip_to_tuple(IPString) ->
    Parts = string:tokens(IPString, "."),
    list_to_tuple([list_to_integer(P) || P <- Parts]).

%% @doc Convert IP tuple to string
-spec tuple_to_ip(ip_address()) -> string().
tuple_to_ip({A, B, C, D}) ->
    lists:flatten(io_lib:format("~p.~p.~p.~p", [A, B, C, D])).

%% @doc Count number of IPs in CIDR range
-spec count_ips(cidr()) -> non_neg_integer().
count_ips(CIDR) ->
    {StartIP, EndIP} = parse_cidr(CIDR),
    ip_to_integer(EndIP) - ip_to_integer(StartIP) + 1.

%% @doc Split CIDR range into chunks of specified size
-spec chunk_range(cidr(), pos_integer()) -> [ip_range()].
chunk_range(CIDR, ChunkSize) ->
    {StartIP, EndIP} = parse_cidr(CIDR),
    StartInt = ip_to_integer(StartIP),
    EndInt = ip_to_integer(EndIP),
    chunk_range_internal(StartInt, EndInt, ChunkSize, []).

%%====================================================================
%% Internal functions
%%====================================================================

%% Parse CIDR notation to IP range
-spec parse_cidr(cidr()) -> ip_range().
parse_cidr(CIDR) ->
    case string:tokens(CIDR, "/") of
        [IPStr, MaskStr] ->
            IP = ip_to_tuple(IPStr),
            Mask = list_to_integer(MaskStr),
            cidr_to_range(IP, Mask);
        [IPStr] ->
            IP = ip_to_tuple(IPStr),
            {IP, IP}
    end.

%% Convert CIDR to IP range
-spec cidr_to_range(ip_address(), 0..32) -> ip_range().
cidr_to_range(IP, Mask) ->
    IPInt = ip_to_integer(IP),
    HostBits = 32 - Mask,
    NetworkMask = (16#FFFFFFFF bsl HostBits) band 16#FFFFFFFF,
    HostMask = 16#FFFFFFFF bsr Mask,
    
    NetworkAddr = IPInt band NetworkMask,
    BroadcastAddr = NetworkAddr bor HostMask,
    
    StartIP = integer_to_ip(NetworkAddr),
    EndIP = integer_to_ip(BroadcastAddr),
    {StartIP, EndIP}.

%% Convert IP tuple to integer
-spec ip_to_integer(ip_address()) -> non_neg_integer().
ip_to_integer({A, B, C, D}) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D.

%% Convert integer to IP tuple
-spec integer_to_ip(non_neg_integer()) -> ip_address().
integer_to_ip(Int) ->
    A = (Int bsr 24) band 16#FF,
    B = (Int bsr 16) band 16#FF,
    C = (Int bsr 8) band 16#FF,
    D = Int band 16#FF,
    {A, B, C, D}.

%% Convert IP range to list (for small ranges only)
-spec range_to_list(ip_address(), ip_address()) -> [ip_address()].
range_to_list(StartIP, EndIP) ->
    Start = ip_to_integer(StartIP),
    End = ip_to_integer(EndIP),
    [integer_to_ip(I) || I <- lists:seq(Start, End)].

%% Create stream generator
-spec make_stream(non_neg_integer(), non_neg_integer()) -> 
    fun(() -> ip_address() | done).
make_stream(Current, End) when Current > End ->
    fun() -> done end;
make_stream(Current, End) ->
    fun() ->
        if
            Current =< End ->
                IP = integer_to_ip(Current),
                {IP, make_stream(Current + 1, End)};
            true ->
                done
        end
    end.

%% Chunk range into smaller ranges
-spec chunk_range_internal(non_neg_integer(), non_neg_integer(), 
                           pos_integer(), [ip_range()]) -> [ip_range()].
chunk_range_internal(Start, End, _ChunkSize, Acc) when Start > End ->
    lists:reverse(Acc);
chunk_range_internal(Start, End, ChunkSize, Acc) ->
    ChunkEnd = min(Start + ChunkSize - 1, End),
    Range = {integer_to_ip(Start), integer_to_ip(ChunkEnd)},
    chunk_range_internal(ChunkEnd + 1, End, ChunkSize, [Range | Acc]).

%%====================================================================
%% Tests
%%====================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

parse_single_ip_test() ->
    ?assertEqual([{192, 168, 1, 1}], parse("192.168.1.1")).

parse_small_cidr_test() ->
    Result = parse("192.168.1.0/30"),
    ?assertEqual(4, length(Result)),
    ?assertEqual({192, 168, 1, 0}, hd(Result)),
    ?assertEqual({192, 168, 1, 3}, lists:last(Result)).

count_ips_test() ->
    ?assertEqual(256, count_ips("192.168.1.0/24")),
    ?assertEqual(65536, count_ips("10.0.0.0/16")),
    ?assertEqual(1, count_ips("192.168.1.1/32")).

ip_conversion_test() ->
    IP = "192.168.1.1",
    Tuple = ip_to_tuple(IP),
    ?assertEqual({192, 168, 1, 1}, Tuple),
    ?assertEqual(IP, tuple_to_ip(Tuple)).

chunk_range_test() ->
    Chunks = chunk_range("192.168.1.0/24", 64),
    ?assertEqual(4, length(Chunks)),
    [{Start, _End} | _] = Chunks,
    ?assertEqual({192, 168, 1, 0}, Start).

stream_test() ->
    Stream = parse_stream("192.168.1.0/30"),
    {IP1, Stream2} = Stream(),
    ?assertEqual({192, 168, 1, 0}, IP1),
    {IP2, Stream3} = Stream2(),
    ?assertEqual({192, 168, 1, 1}, IP2),
    {IP3, Stream4} = Stream3(),
    ?assertEqual({192, 168, 1, 2}, IP3),
    {IP4, Stream5} = Stream4(),
    ?assertEqual({192, 168, 1, 3}, IP4),
    ?assertEqual(done, Stream5()).

-endif.
