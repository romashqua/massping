%%%-------------------------------------------------------------------
%%% @doc Service Version Detector - identify service versions
%%% Enhanced banner grabbing with service signatures
%%% @end
%%%-------------------------------------------------------------------
-module(service_detector).

-export([
    detect/3,
    detect_from_banner/2,
    get_service_name/1,
    get_probe/1
]).

%%====================================================================
%% Types
%%====================================================================

-type service_info() :: #{
    name := string(),
    version => string(),
    product => string(),
    os => string(),
    extra => map()
}.

-export_type([service_info/0]).

%%====================================================================
%% Service signatures (regex patterns)
%%====================================================================

-define(SIGNATURES, [
    %% SSH
    {ssh, <<"^SSH-([0-9.]+)-(.+?)(?:\\r?\\n|$)">>, 
        fun(Match) -> 
            #{name => "SSH", protocol => Match} 
        end},
    
    %% HTTP/HTTPS
    {http, <<"^HTTP/([0-9.]+) ">>,
        fun(_) -> #{name => "HTTP"} end},
    {http_server, <<"Server: (.+?)(?:\\r?\\n|$)">>,
        fun(Match) -> #{product => Match} end},
    {http_powered, <<"X-Powered-By: (.+?)(?:\\r?\\n|$)">>,
        fun(Match) -> #{extra => #{powered_by => Match}} end},
    
    %% FTP
    {ftp, <<"^220[ -](.+?)(?:\\r?\\n|$)">>,
        fun(Match) -> #{name => "FTP", banner => Match} end},
    {vsftpd, <<"vsftpd ([0-9.]+)">>,
        fun(Match) -> #{product => "vsftpd", version => Match} end},
    {proftpd, <<"ProFTPD ([0-9.]+)">>,
        fun(Match) -> #{product => "ProFTPD", version => Match} end},
    
    %% SMTP
    {smtp, <<"^220[ -](.+?) ">>,
        fun(Match) -> #{name => "SMTP", hostname => Match} end},
    {postfix, <<"Postfix">>,
        fun(_) -> #{product => "Postfix"} end},
    {exim, <<"Exim ([0-9.]+)">>,
        fun(Match) -> #{product => "Exim", version => Match} end},
    
    %% MySQL
    {mysql, <<"^.\\x00\\x00\\x00\\x0a([0-9.]+)">>,
        fun(Match) -> #{name => "MySQL", version => Match} end},
    {mariadb, <<"MariaDB">>,
        fun(_) -> #{product => "MariaDB"} end},
    
    %% PostgreSQL
    {postgresql, <<"PostgreSQL">>,
        fun(_) -> #{name => "PostgreSQL"} end},
    
    %% Redis
    {redis, <<"^-ERR|^\\+PONG|^\\$">>,
        fun(_) -> #{name => "Redis"} end},
    {redis_ver, <<"redis_version:([0-9.]+)">>,
        fun(Match) -> #{version => Match} end},
    
    %% MongoDB
    {mongodb, <<"^.*ismaster">>,
        fun(_) -> #{name => "MongoDB"} end},
    
    %% Nginx
    {nginx, <<"nginx/([0-9.]+)">>,
        fun(Match) -> #{product => "nginx", version => Match} end},
    
    %% Apache
    {apache, <<"Apache/([0-9.]+)">>,
        fun(Match) -> #{product => "Apache", version => Match} end},
    
    %% OpenSSH
    {openssh, <<"OpenSSH_([0-9.p]+)">>,
        fun(Match) -> #{product => "OpenSSH", version => Match} end},
    
    %% Dropbear SSH
    {dropbear, <<"dropbear_([0-9.]+)">>,
        fun(Match) -> #{product => "Dropbear", version => Match} end},
    
    %% Telnet
    {telnet, <<"^\\xff\\xfd|^\\xff\\xfb|login:|Username:">>,
        fun(_) -> #{name => "Telnet"} end},
    
    %% RDP
    {rdp, <<"^\\x03\\x00\\x00">>,
        fun(_) -> #{name => "RDP"} end},
    
    %% VNC
    {vnc, <<"^RFB ([0-9.]+)">>,
        fun(Match) -> #{name => "VNC", version => Match} end},
    
    %% IMAP
    {imap, <<"^\\* OK .*(IMAP|Dovecot|Cyrus)">>,
        fun(_) -> #{name => "IMAP"} end},
    
    %% POP3  
    {pop3, <<"^\\+OK .*(POP3|Dovecot|ready)">>,
        fun(_) -> #{name => "POP3"} end},
    
    %% Memcached
    {memcached, <<"^VERSION ([0-9.]+)">>,
        fun(Match) -> #{name => "Memcached", version => Match} end},
    
    %% Elasticsearch
    {elasticsearch, <<"\"cluster_name\"">>,
        fun(_) -> #{name => "Elasticsearch"} end},
    
    %% Docker
    {docker, <<"Docker">>,
        fun(_) -> #{name => "Docker API"} end}
]).

%%====================================================================
%% Probes for specific ports
%%====================================================================

-define(PORT_PROBES, #{
    %% HTTP ports
    80 => <<"GET / HTTP/1.0\r\nHost: target\r\n\r\n">>,
    443 => <<"GET / HTTP/1.0\r\nHost: target\r\n\r\n">>,
    8080 => <<"GET / HTTP/1.0\r\nHost: target\r\n\r\n">>,
    8443 => <<"GET / HTTP/1.0\r\nHost: target\r\n\r\n">>,
    
    %% Redis
    6379 => <<"PING\r\n">>,
    
    %% Memcached
    11211 => <<"version\r\n">>,
    
    %% MySQL
    3306 => <<>>,  %% MySQL sends banner on connect
    
    %% PostgreSQL
    5432 => <<0,0,0,8,4,210,22,47>>,  %% SSL request
    
    %% MongoDB
    27017 => <<58,0,0,0,0,0,0,0,0,0,0,0,212,7,0,0,0,0,0,0,
               "admin.$cmd", 0,0,0,0,0,255,255,255,255,
               19,0,0,0,16,"ismaster",0,1,0,0,0,0>>,
    
    %% Elasticsearch
    9200 => <<"GET / HTTP/1.0\r\n\r\n">>,
    
    %% Default - just connect
    default => <<>>
}).

%%====================================================================
%% API
%%====================================================================

%% @doc Detect service version by connecting and grabbing banner
-spec detect(inet:ip_address(), inet:port_number(), pos_integer()) ->
    {ok, service_info()} | {error, term()}.
detect(IP, Port, Timeout) ->
    Probe = get_probe(Port),
    case gen_tcp:connect(IP, Port, [binary, {active, false}, {packet, raw}], Timeout) of
        {ok, Socket} ->
            Result = case Probe of
                <<>> ->
                    %% Just read banner
                    gen_tcp:recv(Socket, 0, Timeout);
                _ ->
                    %% Send probe and read response
                    gen_tcp:send(Socket, Probe),
                    gen_tcp:recv(Socket, 0, Timeout)
            end,
            gen_tcp:close(Socket),
            case Result of
                {ok, Banner} ->
                    {ok, detect_from_banner(Port, Banner)};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Detect service from banner
-spec detect_from_banner(inet:port_number(), binary()) -> service_info().
detect_from_banner(Port, Banner) ->
    BaseInfo = #{
        name => get_service_name(Port),
        raw_banner => truncate_banner(Banner)
    },
    match_signatures(Banner, BaseInfo).

%% @doc Get default service name for port
-spec get_service_name(inet:port_number()) -> string().
get_service_name(21) -> "FTP";
get_service_name(22) -> "SSH";
get_service_name(23) -> "Telnet";
get_service_name(25) -> "SMTP";
get_service_name(53) -> "DNS";
get_service_name(80) -> "HTTP";
get_service_name(110) -> "POP3";
get_service_name(143) -> "IMAP";
get_service_name(443) -> "HTTPS";
get_service_name(445) -> "SMB";
get_service_name(993) -> "IMAPS";
get_service_name(995) -> "POP3S";
get_service_name(1433) -> "MSSQL";
get_service_name(1521) -> "Oracle";
get_service_name(3306) -> "MySQL";
get_service_name(3389) -> "RDP";
get_service_name(5432) -> "PostgreSQL";
get_service_name(5900) -> "VNC";
get_service_name(6379) -> "Redis";
get_service_name(8080) -> "HTTP-Proxy";
get_service_name(8443) -> "HTTPS-Alt";
get_service_name(9200) -> "Elasticsearch";
get_service_name(11211) -> "Memcached";
get_service_name(27017) -> "MongoDB";
get_service_name(_) -> "Unknown".

%% @doc Get probe for port
-spec get_probe(inet:port_number()) -> binary().
get_probe(Port) ->
    maps:get(Port, ?PORT_PROBES, maps:get(default, ?PORT_PROBES)).

%%====================================================================
%% Internal functions  
%%====================================================================

match_signatures(Banner, Info) ->
    lists:foldl(fun({_Name, Pattern, ExtractFun}, Acc) ->
        case re:run(Banner, Pattern, [{capture, all_but_first, binary}]) of
            {match, [Match | _]} ->
                maps:merge(Acc, ExtractFun(Match));
            {match, []} ->
                maps:merge(Acc, ExtractFun(<<>>));
            nomatch ->
                Acc
        end
    end, Info, ?SIGNATURES).

truncate_banner(Banner) when byte_size(Banner) > 256 ->
    <<First:256/binary, _/binary>> = Banner,
    First;
truncate_banner(Banner) ->
    Banner.
