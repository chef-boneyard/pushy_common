%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92-*-
%% ex: ts=4 sw=4 et
%% @author James Casey <james@opscode.com>
%% @copyright 2012 Opscode, Inc.

%% @doc  Retrieve configuration from a pushy server via HTTP
-module(pushy_client_config).

-export([
         get_config/3
        ]).

%% for dialyzer
%%-type config_key() ::  heartbeat_address | command_address | public_key.

-spec get_config(OrgName :: binary(),
                 Hostname :: binary(),
                 Port :: integer()) -> list().
%% @doc retrieve the configuration for a pushy server from the REST config
%% endpoint
get_config(OrgName, Hostname, Port) ->
    FullHeaders = [{"Accept", "application/json"}],
    Url = construct_url(OrgName, Hostname, Port),
    case ibrowse:send_req(Url, FullHeaders, get) of
        {ok, Code, ResponseHeaders, ResponseBody} ->
            ok = check_http_response(Code, ResponseHeaders, ResponseBody),
            parse_json_response(ResponseBody);
        {error, Reason} ->
            throw({error, Reason})
    end.

-spec parse_json_response(Body::string()) -> list().
%% @doc Parse the configuration response body and return the heartbeat
%% and command channel addresses along with the public key
%% for the server.
%%
%% We convert the zeromq addresses to lists since it doesn't support
%% binary endpoints
parse_json_response(Body) ->
    EJson = jiffy:decode(Body),
    HeartbeatAddress = ej:get({"push_jobs", "heartbeat", "out_addr"}, EJson),
    CommandAddress = ej:get({"push_jobs", "heartbeat", "command_addr"}, EJson),
    PublicKey = ej:get({"public_key"}, EJson),
    [{heartbeat_address, binary_to_list(HeartbeatAddress)},
     {command_address, binary_to_list(CommandAddress)},
     {public_key, PublicKey}].

%% @doc Check the code of the HTTP response and throw error if non-2XX
%%
check_http_response(Code, Headers, Body) ->
    case Code of
        "2" ++ _Digits ->
            ok;
        "3" ++ _Digits ->
            throw({error, {redirection, {Code, Headers, Body}}});
        "404" ->
            throw({error, {not_found, {Code, Headers, Body}}});
        "4" ++ _Digits ->
            throw({error, {client_error, {Code, Headers, Body}}});
        "5" ++ _Digits ->
            throw({error, {server_error, {Code, Headers, Body}}})
    end.


-spec construct_url(OrgName :: binary(),
                    Hostname :: binary(),
                    Port :: integer()) -> list().
construct_url(OrgName, Hostname, Port) ->
    lists:flatten(io_lib:format("http://~s:~w/organizations/~s/pushy/config", [Hostname, Port, OrgName])).
