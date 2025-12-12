%%%-------------------------------------------------------------------
%%% @doc MassPing REST API Handler
%%% HTTP API for scan management
%%% @end
%%%-------------------------------------------------------------------
-module(massping_api_handler).

-export([init/2]).

%%====================================================================
%% Cowboy Handler
%%====================================================================

init(Req0, State) ->
    Method = cowboy_req:method(Req0),
    Path = cowboy_req:path(Req0),
    {ok, handle(Method, Path, Req0), State}.

%%====================================================================
%% Route Handlers
%%====================================================================

%% GET /api/status - Server status
handle(<<"GET">>, <<"/api/status">>, Req) ->
    respond_json(Req, #{
        status => ok,
        version => <<"1.0.0">>,
        node => atom_to_binary(node()),
        uptime => element(1, erlang:statistics(wall_clock)),
        memory => erlang:memory(total),
        process_count => erlang:system_info(process_count)
    });

%% GET /api/scans - List active scans
handle(<<"GET">>, <<"/api/scans">>, Req) ->
    Scans = massping_scan_manager:list_scans(),
    respond_json(Req, #{scans => Scans});

%% POST /api/scans - Start new scan
handle(<<"POST">>, <<"/api/scans">>, Req0) ->
    {ok, Body, Req} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"cidrs">> := CIDRs, <<"ports">> := Ports} = Params ->
            Options = maps:without([<<"cidrs">>, <<"ports">>], Params),
            case massping_scan_manager:start_scan(CIDRs, Ports, Options) of
                {ok, ScanId} ->
                    respond_json(Req, #{scan_id => ScanId, status => started}, 201);
                {error, Reason} ->
                    respond_error(Req, Reason, 400)
            end;
        _ ->
            respond_error(Req, <<"Invalid request body">>, 400)
    end;

%% GET /api/scans/:id or /api/scans/:id/results - Get scan status or results
handle(<<"GET">>, <<"/api/scans/", Rest/binary>>, Req) ->
    case binary:split(Rest, <<"/">>, [global, trim_all]) of
        [ScanId, <<"results">>] ->
            case massping_scan_manager:get_results(ScanId) of
                {ok, Results} ->
                    respond_json(Req, #{results => Results});
                {error, Reason} ->
                    respond_error(Req, Reason, 404)
            end;
        [ScanId] ->
            case massping_scan_manager:get_scan(ScanId) of
                {ok, ScanInfo} ->
                    respond_json(Req, ScanInfo);
                {error, not_found} ->
                    respond_error(Req, <<"Scan not found">>, 404)
            end;
        _ ->
            respond_error(Req, <<"Not found">>, 404)
    end;

%% DELETE /api/scans/:id - Stop/cancel scan
handle(<<"DELETE">>, <<"/api/scans/", ScanId/binary>>, Req) ->
    case massping_scan_manager:stop_scan(ScanId) of
        ok ->
            respond_json(Req, #{status => stopped});
        {error, Reason} ->
            respond_error(Req, Reason, 400)
    end;

%% GET /api/sessions - List saved sessions (for resume)
handle(<<"GET">>, <<"/api/sessions">>, Req) ->
    Sessions = scan_state:list_sessions(),
    SessionList = [#{
        id => list_to_binary(Id),
        last_updated => Ts,
        progress => Progress
    } || {Id, Ts, Progress} <- Sessions],
    respond_json(Req, #{sessions => SessionList});

%% POST /api/sessions/:id/resume - Resume saved session
handle(<<"POST">>, <<"/api/sessions/", Rest/binary>>, Req) ->
    case binary:split(Rest, <<"/">>, [global, trim_all]) of
        [SessionId, <<"resume">>] ->
            case scan_state:load(binary_to_list(SessionId)) of
                {ok, State} ->
                    case massping_scan_manager:resume_scan(State) of
                        {ok, ScanId} ->
                            respond_json(Req, #{scan_id => ScanId, status => resumed});
                        {error, Reason} ->
                            respond_error(Req, Reason, 400)
                    end;
                {error, Reason} ->
                    respond_error(Req, Reason, 404)
            end;
        _ ->
            respond_error(Req, <<"Invalid session path">>, 400)
    end;

%% GET /api/cluster - Cluster status
handle(<<"GET">>, <<"/api/cluster">>, Req) ->
    Nodes = [node() | nodes()],
    NodeInfos = [#{
        node => atom_to_binary(N),
        connected => lists:member(N, [node() | nodes()]),
        status => case net_adm:ping(N) of pong -> online; _ -> offline end
    } || N <- Nodes],
    respond_json(Req, #{
        nodes => NodeInfos,
        total_nodes => length(Nodes)
    });

%% POST /api/cluster/nodes - Add node to cluster
handle(<<"POST">>, <<"/api/cluster/nodes">>, Req0) ->
    {ok, Body, Req} = cowboy_req:read_body(Req0),
    case jsx:decode(Body, [return_maps]) of
        #{<<"node">> := NodeBin} ->
            Node = binary_to_atom(NodeBin),
            case net_adm:ping(Node) of
                pong ->
                    respond_json(Req, #{status => connected, node => NodeBin});
                pang ->
                    respond_error(Req, <<"Cannot connect to node">>, 400)
            end;
        _ ->
            respond_error(Req, <<"Invalid request">>, 400)
    end;

%% Not found
handle(_, _, Req) ->
    respond_error(Req, <<"Not found">>, 404).

%%====================================================================
%% Response helpers
%%====================================================================

respond_json(Req, Data) ->
    respond_json(Req, Data, 200).

respond_json(Req, Data, Status) ->
    Json = jsx:encode(Data),
    cowboy_req:reply(Status, #{
        <<"content-type">> => <<"application/json">>
    }, Json, Req).

respond_error(Req, Message, Status) when is_atom(Message) ->
    respond_error(Req, atom_to_binary(Message), Status);
respond_error(Req, Message, Status) ->
    respond_json(Req, #{error => Message}, Status).
