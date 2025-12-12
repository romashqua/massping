%%%-------------------------------------------------------------------
%%% @doc UDP Scanner - scan UDP ports
%%% Uses probe packets to detect open UDP ports.
%%% 
%%% UDP scanning is harder than TCP because:
%%% - No handshake (no clear "open" signal)
%%% - ICMP "port unreachable" = closed
%%% - No response = open or filtered
%%% 
%%% We use service-specific probes to get responses.
%%% @end
%%%-------------------------------------------------------------------
-module(udp_scanner).

-export([
    scan/3,
    scan_batch/2,
    get_probe/1,
    is_service_response/2
]).

-define(DEFAULT_TIMEOUT, 2000).

%%====================================================================
%% Common UDP port probes
%%====================================================================

%% DNS query for version.bind (port 53)
-define(DNS_PROBE, <<
    16#00, 16#01,  %% Transaction ID
    16#01, 16#00,  %% Flags: standard query
    16#00, 16#01,  %% Questions: 1
    16#00, 16#00,  %% Answer RRs
    16#00, 16#00,  %% Authority RRs
    16#00, 16#00,  %% Additional RRs
    16#07, "version", 16#04, "bind", 16#00,  %% Query name
    16#00, 16#10,  %% Type: TXT
    16#00, 16#03   %% Class: CH (Chaos)
>>).

%% NTP version request (port 123)
-define(NTP_PROBE, <<
    16#E3,         %% LI=3, VN=4, Mode=3 (client)
    16#00,         %% Stratum
    16#06,         %% Poll
    16#EC,         %% Precision
    0:32,          %% Root Delay
    0:32,          %% Root Dispersion
    0:32,          %% Reference ID
    0:64,          %% Reference Timestamp
    0:64,          %% Origin Timestamp
    0:64,          %% Receive Timestamp
    0:64           %% Transmit Timestamp
>>).

%% SNMP GetRequest (port 161)
-define(SNMP_PROBE, <<
    16#30, 16#26,  %% SEQUENCE
    16#02, 16#01, 16#00,  %% Version: 1
    16#04, 16#06, "public",  %% Community: public
    16#A0, 16#19,  %% GetRequest-PDU
    16#02, 16#04, 16#00, 16#00, 16#00, 16#01,  %% Request ID
    16#02, 16#01, 16#00,  %% Error Status
    16#02, 16#01, 16#00,  %% Error Index
    16#30, 16#0B,  %% Varbind list
    16#30, 16#09,  %% Varbind
    16#06, 16#05, 16#2B, 16#06, 16#01, 16#02, 16#01,  %% OID: 1.3.6.1.2.1 (system)
    16#05, 16#00   %% NULL value
>>).

%% SSDP M-SEARCH (port 1900)
-define(SSDP_PROBE, <<"M-SEARCH * HTTP/1.1\r\n",
    "HOST: 239.255.255.250:1900\r\n",
    "MAN: \"ssdp:discover\"\r\n",
    "MX: 1\r\n",
    "ST: ssdp:all\r\n\r\n">>).

%% NetBIOS Name Service query (port 137)
-define(NETBIOS_PROBE, <<
    16#80, 16#01,  %% Transaction ID
    16#00, 16#10,  %% Flags
    16#00, 16#01,  %% Questions
    16#00, 16#00,  %% Answer RRs
    16#00, 16#00,  %% Authority RRs
    16#00, 16#00,  %% Additional RRs
    16#20,         %% Name length
    "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  %% Encoded *
    16#00,         %% Null terminator
    16#00, 16#21,  %% Type: NBSTAT
    16#00, 16#01   %% Class: IN
>>).

%% SIP OPTIONS (port 5060)
-define(SIP_PROBE, <<"OPTIONS sip:nm SIP/2.0\r\n",
    "Via: SIP/2.0/UDP nm;branch=foo\r\n",
    "From: <sip:nm@nm>;tag=root\r\n",
    "To: <sip:nm2@nm2>\r\n",
    "Call-ID: 50000\r\n",
    "CSeq: 42 OPTIONS\r\n",
    "Max-Forwards: 70\r\n",
    "Content-Length: 0\r\n",
    "Contact: <sip:nm@nm>\r\n",
    "Accept: application/sdp\r\n\r\n">>).

%% Generic empty probe
-define(GENERIC_PROBE, <<0, 0, 0, 0>>).

%%====================================================================
%% API
%%====================================================================

%% @doc Scan single UDP port
-spec scan(inet:ip_address(), inet:port_number(), pos_integer()) ->
    {open | closed | open_filtered, inet:port_number()} | 
    {open, inet:port_number(), binary()}.
scan(IP, Port, Timeout) ->
    Probe = get_probe(Port),
    case gen_udp:open(0, [binary, {active, false}]) of
        {ok, Socket} ->
            Result = do_scan(Socket, IP, Port, Probe, Timeout),
            gen_udp:close(Socket),
            Result;
        {error, _} ->
            {open_filtered, Port}
    end.

%% @doc Scan batch of targets
-spec scan_batch([{inet:ip_address(), inet:port_number()}], pos_integer()) ->
    [{inet:ip_address(), open | closed | open_filtered, inet:port_number()}].
scan_batch(Targets, Timeout) ->
    %% Parallel UDP scan with limited concurrency
    Parent = self(),
    Ref = make_ref(),
    
    %% Spawn workers for each target
    Pids = [spawn_link(fun() ->
        Result = scan(IP, Port, Timeout),
        Parent ! {Ref, IP, Result}
    end) || {IP, Port} <- Targets],
    
    %% Collect results
    collect_results(Ref, length(Pids), []).

%% @doc Get appropriate probe for port
-spec get_probe(inet:port_number()) -> binary().
get_probe(53) -> ?DNS_PROBE;
get_probe(123) -> ?NTP_PROBE;
get_probe(161) -> ?SNMP_PROBE;
get_probe(162) -> ?SNMP_PROBE;
get_probe(137) -> ?NETBIOS_PROBE;
get_probe(1900) -> ?SSDP_PROBE;
get_probe(5060) -> ?SIP_PROBE;
get_probe(5061) -> ?SIP_PROBE;
get_probe(_) -> ?GENERIC_PROBE.

%% @doc Check if response indicates service
-spec is_service_response(inet:port_number(), binary()) -> {true, string()} | false.
is_service_response(53, <<_:16, 16#81, _/binary>>) ->
    {true, "DNS"};
is_service_response(53, <<_:16, 16#84, _/binary>>) ->
    {true, "DNS"};
is_service_response(123, <<16#1C, _/binary>>) ->
    {true, "NTP"};
is_service_response(123, <<16#24, _/binary>>) ->
    {true, "NTP"};
is_service_response(161, <<16#30, _/binary>>) ->
    {true, "SNMP"};
is_service_response(137, <<_:16, 16#84, _/binary>>) ->
    {true, "NetBIOS"};
is_service_response(1900, <<"HTTP/1.1", _/binary>>) ->
    {true, "SSDP/UPnP"};
is_service_response(5060, <<"SIP/2.0", _/binary>>) ->
    {true, "SIP"};
is_service_response(_, _) ->
    false.

%%====================================================================
%% Internal functions
%%====================================================================

do_scan(Socket, IP, Port, Probe, Timeout) ->
    %% Send probe
    case gen_udp:send(Socket, IP, Port, Probe) of
        ok ->
            %% Wait for response or ICMP unreachable
            case gen_udp:recv(Socket, 0, Timeout) of
                {ok, {_FromIP, _FromPort, Data}} ->
                    %% Got response - port is open
                    case is_service_response(Port, Data) of
                        {true, Service} ->
                            {open, Port, list_to_binary(Service)};
                        false ->
                            {open, Port, Data}
                    end;
                {error, etimedout} ->
                    %% No response - open or filtered
                    {open_filtered, Port};
                {error, econnrefused} ->
                    %% ICMP port unreachable - closed
                    {closed, Port};
                {error, _} ->
                    {open_filtered, Port}
            end;
        {error, _} ->
            {open_filtered, Port}
    end.

collect_results(_Ref, 0, Acc) ->
    Acc;
collect_results(Ref, N, Acc) ->
    receive
        {Ref, IP, {Status, Port}} ->
            collect_results(Ref, N - 1, [{IP, Status, Port} | Acc]);
        {Ref, IP, {Status, Port, _Banner}} ->
            collect_results(Ref, N - 1, [{IP, Status, Port} | Acc])
    after 30000 ->
        Acc
    end.
