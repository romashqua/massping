%%%-------------------------------------------------------------------
%%% @doc Service banner grabbing and fingerprinting
%%% 
%%% Grabs service banners from open ports to identify:
%%% - Service name and version
%%% - Operating system hints
%%% - Known vulnerabilities
%%% @end
%%%-------------------------------------------------------------------
-module(banner_grabber).

-export([
    grab/3,
    grab_async/4,
    identify_service/2,
    get_probe/1
]).

%% Common service probes
-define(PROBES, #{
    http => <<"GET / HTTP/1.0\r\nHost: target\r\n\r\n">>,
    https => <<"">>,  % SSL handshake handled separately
    ssh => <<"">>,    % SSH sends banner first
    ftp => <<"">>,    % FTP sends banner first
    smtp => <<"EHLO scanner\r\n">>,
    mysql => <<"">>,  % MySQL sends greeting
    redis => <<"INFO\r\n">>,
    memcached => <<"stats\r\n">>,
    mongodb => <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>,  % Minimal OP_MSG
    postgres => <<0,0,0,8,4,210,22,47>>,  % SSL request
    telnet => <<255,251,1,255,251,3>>  % IAC WILL ECHO, IAC WILL SGA
}).

%% Service signatures (regex patterns)
-define(SIGNATURES, [
    {<<"SSH-">>, ssh, fun parse_ssh_banner/1},
    {<<"HTTP/">>, http, fun parse_http_banner/1},
    {<<"220">>, smtp_or_ftp, fun parse_220_banner/1},
    {<<"MySQL">>, mysql, fun parse_mysql_banner/1},
    {<<"redis_version">>, redis, fun parse_redis_banner/1},
    {<<"STAT">>, memcached, fun parse_memcached_banner/1},
    {<<"PostgreSQL">>, postgres, fun parse_postgres_banner/1},
    {<<"MongoDB">>, mongodb, fun parse_mongodb_banner/1}
]).

%%====================================================================
%% API
%%====================================================================

%% @doc Grab banner from an open port (blocking)
-spec grab(tuple(), pos_integer(), pos_integer()) -> 
    {ok, binary(), map()} | {error, term()}.
grab(IP, Port, Timeout) ->
    Probe = get_probe(Port),
    case gen_tcp:connect(IP, Port, [binary, {active, false}, {packet, raw}], Timeout) of
        {ok, Socket} ->
            Result = try
                %% Send probe if needed
                case Probe of
                    <<>> -> ok;
                    _ -> gen_tcp:send(Socket, Probe)
                end,
                
                %% Receive banner (with timeout)
                case gen_tcp:recv(Socket, 0, Timeout) of
                    {ok, Data} ->
                        ServiceInfo = identify_service(Port, Data),
                        {ok, Data, ServiceInfo};
                    {error, Reason} ->
                        {error, Reason}
                end
            after
                gen_tcp:close(Socket)
            end,
            Result;
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Grab banner asynchronously
-spec grab_async(tuple(), pos_integer(), pos_integer(), pid()) -> pid().
grab_async(IP, Port, Timeout, ReplyTo) ->
    spawn(fun() ->
        Result = grab(IP, Port, Timeout),
        ReplyTo ! {banner_result, IP, Port, Result}
    end).

%% @doc Identify service from banner
-spec identify_service(pos_integer(), binary()) -> map().
identify_service(Port, Banner) ->
    %% Try signature matching first
    case match_signature(Banner) of
        {ok, Service, Parser} ->
            Info = Parser(Banner),
            Info#{service => Service, port => Port};
        nomatch ->
            %% Fall back to port-based guess
            #{
                service => port_to_service(Port),
                port => Port,
                banner => truncate_banner(Banner),
                identified_by => port_guess
            }
    end.

%% @doc Get probe for a port
-spec get_probe(pos_integer()) -> binary().
get_probe(80) -> maps:get(http, ?PROBES);
get_probe(8080) -> maps:get(http, ?PROBES);
get_probe(8000) -> maps:get(http, ?PROBES);
get_probe(443) -> maps:get(https, ?PROBES);
get_probe(22) -> maps:get(ssh, ?PROBES);
get_probe(21) -> maps:get(ftp, ?PROBES);
get_probe(25) -> maps:get(smtp, ?PROBES);
get_probe(587) -> maps:get(smtp, ?PROBES);
get_probe(3306) -> maps:get(mysql, ?PROBES);
get_probe(6379) -> maps:get(redis, ?PROBES);
get_probe(11211) -> maps:get(memcached, ?PROBES);
get_probe(27017) -> maps:get(mongodb, ?PROBES);
get_probe(5432) -> maps:get(postgres, ?PROBES);
get_probe(23) -> maps:get(telnet, ?PROBES);
get_probe(_) -> <<>>.

%%====================================================================
%% Internal functions
%%====================================================================

match_signature(Banner) ->
    match_signature(Banner, ?SIGNATURES).

match_signature(_Banner, []) ->
    nomatch;
match_signature(Banner, [{Prefix, Service, Parser} | Rest]) ->
    case binary:match(Banner, Prefix) of
        {_, _} -> {ok, Service, Parser};
        nomatch -> match_signature(Banner, Rest)
    end.

%% SSH banner parser
parse_ssh_banner(Banner) ->
    %% SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
    case re:run(Banner, <<"SSH-([0-9.]+)-([^\r\n]+)">>, [{capture, all_but_first, binary}]) of
        {match, [Version, Software]} ->
            #{
                version => Version,
                software => Software,
                banner => truncate_banner(Banner),
                identified_by => banner
            };
        nomatch ->
            #{banner => truncate_banner(Banner), identified_by => partial}
    end.

%% HTTP banner parser
parse_http_banner(Banner) ->
    %% HTTP/1.1 200 OK\r\nServer: nginx/1.18.0
    ServerHeader = case re:run(Banner, <<"Server: ([^\r\n]+)">>, [{capture, all_but_first, binary}]) of
        {match, [Server]} -> Server;
        nomatch -> <<"unknown">>
    end,
    StatusCode = case re:run(Banner, <<"HTTP/[0-9.]+ ([0-9]+)">>, [{capture, all_but_first, binary}]) of
        {match, [Code]} -> binary_to_integer(Code);
        nomatch -> 0
    end,
    #{
        server => ServerHeader,
        status_code => StatusCode,
        banner => truncate_banner(Banner),
        identified_by => banner
    }.

%% 220 banner (SMTP or FTP)
parse_220_banner(Banner) ->
    Service = case binary:match(Banner, [<<"SMTP">>, <<"smtp">>, <<"ESMTP">>, <<"Postfix">>, <<"Sendmail">>]) of
        {_, _} -> smtp;
        nomatch ->
            case binary:match(Banner, [<<"FTP">>, <<"ftp">>, <<"FileZilla">>, <<"vsftpd">>]) of
                {_, _} -> ftp;
                nomatch -> unknown_220
            end
    end,
    #{
        subservice => Service,
        banner => truncate_banner(Banner),
        identified_by => banner
    }.

%% MySQL banner parser
parse_mysql_banner(Banner) ->
    %% Extract version from MySQL greeting packet
    #{
        banner => truncate_banner(Banner),
        identified_by => banner
    }.

%% Redis banner parser
parse_redis_banner(Banner) ->
    Version = case re:run(Banner, <<"redis_version:([^\r\n]+)">>, [{capture, all_but_first, binary}]) of
        {match, [V]} -> V;
        nomatch -> <<"unknown">>
    end,
    #{
        version => Version,
        banner => truncate_banner(Banner),
        identified_by => banner
    }.

%% Memcached parser
parse_memcached_banner(Banner) ->
    Version = case re:run(Banner, <<"version ([^\r\n]+)">>, [{capture, all_but_first, binary}]) of
        {match, [V]} -> V;
        nomatch -> <<"unknown">>
    end,
    #{
        version => Version,
        banner => truncate_banner(Banner),
        identified_by => banner
    }.

%% PostgreSQL parser
parse_postgres_banner(Banner) ->
    #{
        banner => truncate_banner(Banner),
        identified_by => banner
    }.

%% MongoDB parser
parse_mongodb_banner(Banner) ->
    #{
        banner => truncate_banner(Banner),
        identified_by => banner
    }.

%% Port to service name mapping
port_to_service(21) -> ftp;
port_to_service(22) -> ssh;
port_to_service(23) -> telnet;
port_to_service(25) -> smtp;
port_to_service(53) -> dns;
port_to_service(80) -> http;
port_to_service(110) -> pop3;
port_to_service(143) -> imap;
port_to_service(443) -> https;
port_to_service(445) -> smb;
port_to_service(587) -> smtp;
port_to_service(993) -> imaps;
port_to_service(995) -> pop3s;
port_to_service(1433) -> mssql;
port_to_service(1521) -> oracle;
port_to_service(3306) -> mysql;
port_to_service(3389) -> rdp;
port_to_service(5432) -> postgres;
port_to_service(5672) -> amqp;
port_to_service(6379) -> redis;
port_to_service(8080) -> http_proxy;
port_to_service(8443) -> https_alt;
port_to_service(9200) -> elasticsearch;
port_to_service(11211) -> memcached;
port_to_service(27017) -> mongodb;
port_to_service(_) -> unknown.

%% Truncate banner for storage
truncate_banner(Banner) when byte_size(Banner) > 256 ->
    <<Truncated:256/binary, _/binary>> = Banner,
    Truncated;
truncate_banner(Banner) ->
    Banner.

%%====================================================================
%% Tests
%%====================================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

ssh_parse_test() ->
    Banner = <<"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n">>,
    Info = parse_ssh_banner(Banner),
    ?assertEqual(<<"2.0">>, maps:get(version, Info)),
    ?assertEqual(<<"OpenSSH_8.9p1 Ubuntu-3ubuntu0.1">>, maps:get(software, Info)).

http_parse_test() ->
    Banner = <<"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n">>,
    Info = parse_http_banner(Banner),
    ?assertEqual(<<"nginx/1.18.0">>, maps:get(server, Info)),
    ?assertEqual(200, maps:get(status_code, Info)).

port_service_test() ->
    ?assertEqual(ssh, port_to_service(22)),
    ?assertEqual(http, port_to_service(80)),
    ?assertEqual(https, port_to_service(443)).

-endif.
