%%%-------------------------------------------------------------------
%%% @doc Exclude Filter - filter out IPs from scanning
%%% Supports:
%%% - Single IPs: 192.168.1.1
%%% - CIDR ranges: 192.168.0.0/24
%%% - Comments: # or //
%%% @end
%%%-------------------------------------------------------------------
-module(exclude_filter).

-export([
    load/1,
    is_excluded/2,
    filter_targets/2,
    new/0,
    add/2,
    add_cidr/2,
    count/1
]).

-record(exclude_set, {
    ips = sets:new() :: sets:set(inet:ip4_address()),
    cidrs = [] :: [{inet:ip4_address(), non_neg_integer()}]  %% {BaseIP, Mask}
}).

-type exclude_set() :: #exclude_set{}.
-export_type([exclude_set/0]).

%%====================================================================
%% API
%%====================================================================

%% @doc Create new empty exclude set
-spec new() -> exclude_set().
new() ->
    #exclude_set{}.

%% @doc Load exclude list from file
%% File format: one IP or CIDR per line, # for comments
-spec load(file:filename()) -> {ok, exclude_set()} | {error, term()}.
load(Filename) ->
    case file:read_file(Filename) of
        {ok, Binary} ->
            Lines = binary:split(Binary, [<<"\n">>, <<"\r">>], [global, trim_all]),
            ExcludeSet = lists:foldl(fun parse_line/2, new(), Lines),
            {ok, ExcludeSet};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Check if IP is excluded
-spec is_excluded(inet:ip4_address(), exclude_set()) -> boolean().
is_excluded(IP, #exclude_set{ips = IPs, cidrs = CIDRs}) ->
    sets:is_element(IP, IPs) orelse is_in_any_cidr(IP, CIDRs).

%% @doc Filter targets, removing excluded IPs
-spec filter_targets([{inet:ip4_address(), inet:port_number()}], exclude_set()) ->
    [{inet:ip4_address(), inet:port_number()}].
filter_targets(Targets, ExcludeSet) ->
    lists:filter(fun({IP, _Port}) -> not is_excluded(IP, ExcludeSet) end, Targets).

%% @doc Add single IP to exclude set
-spec add(inet:ip4_address(), exclude_set()) -> exclude_set().
add(IP, #exclude_set{ips = IPs} = Set) ->
    Set#exclude_set{ips = sets:add_element(IP, IPs)}.

%% @doc Add CIDR range to exclude set
-spec add_cidr(string() | binary(), exclude_set()) -> exclude_set().
add_cidr(CIDR, Set) when is_binary(CIDR) ->
    add_cidr(binary_to_list(CIDR), Set);
add_cidr(CIDR, #exclude_set{cidrs = CIDRs} = Set) ->
    case parse_cidr(CIDR) of
        {ok, BaseIP, Mask} ->
            Set#exclude_set{cidrs = [{BaseIP, Mask} | CIDRs]};
        error ->
            Set
    end.

%% @doc Count excluded entries (IPs + CIDRs)
-spec count(exclude_set()) -> {non_neg_integer(), non_neg_integer()}.
count(#exclude_set{ips = IPs, cidrs = CIDRs}) ->
    {sets:size(IPs), length(CIDRs)}.

%%====================================================================
%% Internal functions
%%====================================================================

parse_line(Line, Set) when is_binary(Line) ->
    parse_line(string:trim(binary_to_list(Line)), Set);
parse_line([], Set) ->
    Set;  %% Empty line
parse_line("#" ++ _, Set) ->
    Set;  %% Comment
parse_line("//" ++ _, Set) ->
    Set;  %% Comment
parse_line(Line, Set) ->
    case string:chr(Line, $/) of
        0 ->
            %% Single IP
            case inet:parse_address(Line) of
                {ok, IP} -> add(IP, Set);
                _ -> Set
            end;
        _ ->
            %% CIDR
            add_cidr(Line, Set)
    end.

parse_cidr(CIDR) ->
    case string:tokens(CIDR, "/") of
        [IPStr, MaskStr] ->
            case inet:parse_address(IPStr) of
                {ok, IP} ->
                    case catch list_to_integer(MaskStr) of
                        Mask when is_integer(Mask), Mask >= 0, Mask =< 32 ->
                            {ok, IP, Mask};
                        _ ->
                            error
                    end;
                _ ->
                    error
            end;
        _ ->
            error
    end.

is_in_any_cidr(_IP, []) ->
    false;
is_in_any_cidr(IP, [{BaseIP, Mask} | Rest]) ->
    case ip_in_cidr(IP, BaseIP, Mask) of
        true -> true;
        false -> is_in_any_cidr(IP, Rest)
    end.

ip_in_cidr({A1, B1, C1, D1}, {A2, B2, C2, D2}, Mask) ->
    IP1Int = (A1 bsl 24) bor (B1 bsl 16) bor (C1 bsl 8) bor D1,
    IP2Int = (A2 bsl 24) bor (B2 bsl 16) bor (C2 bsl 8) bor D2,
    MaskBits = (16#FFFFFFFF bsl (32 - Mask)) band 16#FFFFFFFF,
    (IP1Int band MaskBits) =:= (IP2Int band MaskBits).
