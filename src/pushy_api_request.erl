%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92-*-
%% ex: ts=4 sw=4 et
%% @author Steven Grady <steven.grady@erlang-solutions.com>

%% @doc  Make requests of a pushy server via HTTP
%% @copyright Copyright 2014 Chef Software, Inc. All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License. You may obtain
%% a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied. See the License for the
%% specific language governing permissions and limitations
%% under the License.

-module(pushy_api_request).

-export([
         do_request/7
        ]).

-include("pushy_messaging.hrl").
-include("pushy_client.hrl").

%----------

%% @doc Sign and send an API request
-spec do_request(PrivateKey :: #'RSAPrivateKey'{},
                 CreatorName :: binary(),
                 Path :: binary(),
                 ServerHost :: binary(),
                 ServerPort :: integer() | undefined,
                 Method :: get | post,
                 Body :: undefined | binary()) ->  {ok, string(), [{string(), string()}], string()}.
do_request(PrivateKey, CreatorName, Path, ServerHost, ServerPort, Method, Body) ->
    BMethod = case Method of
                  get -> <<"GET">>;
                  post -> <<"POST">>
              end,
    BBody = case Body of
                undefined -> <<"">>;
                _ -> Body
            end,
    Headers =  chef_authn:sign_request(PrivateKey, BBody, CreatorName,
                                       BMethod, now, Path),
    FullHeaders = [{"Accept", "application/json"}, {"Content-Type", "application/json"}
                   |Headers],
    Url = construct_url(ServerHost, ServerPort, Path),
    case ibrowse:send_req(Url, FullHeaders, Method, BBody) of
        Response = {ok, Code, ResponseHeaders, ResponseBody} ->
            ok = check_http_response(Code, ResponseHeaders, ResponseBody),
            Response;
        {error, Reason} ->
            throw({error, Reason})
    end.

%% @doc Check the code of the HTTP response and throw error if non-2XX/3XX
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


-spec construct_url(Hostname :: binary(),
                    Port :: integer() | undefined,
                    Path :: binary()) -> list().
construct_url(Hostname, undefined, Path) ->
    lists:flatten(io_lib:format("http://~s/~s", [Hostname, Path]));
construct_url(Hostname, Port, Path) ->
    lists:flatten(io_lib:format("http://~s:~w/~s", [Hostname, Port, Path])).
