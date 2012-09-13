%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92-*-
%% ex: ts=4 sw=4 et
%% @author James Casey <james@opscode.com>
%% Copyright 2012 Opscode, Inc. All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%


-module(pushy_client_config_tests).


-include_lib("eunit/include/eunit.hrl").

setup_env() ->
    ok.

make_response_body() ->
    jiffy:encode({[{<<"type">>,<<"config">>},
                   {<<"host">>,<<"localhost">>},
                   {<<"push_jobs">>,
                    {[{<<"heartbeat">>,
                       {[{<<"out_addr">>,<<"tcp://localhost:10000">>},
                         {<<"command_addr">>,<<"tcp://localhost:10002">>},
                         {<<"interval">>,1.0},
                         {<<"offline_threshold">>,3},
                         {<<"online_threshold">>,2}]}}]}},
                   {<<"public_key">>,
                    <<"-----BEGIN PUBLIC KEY-----\n">>},
                   {<<"lifetime">>,3600}]}).


simple_test_() ->
    MockedModules = [ibrowse],
    %% request data
    OrgName = <<"clownco">>,
    Hostname = <<"localhost">>,
    Port = 10002,

    {foreach,
     fun() ->
             setup_env(),
             meck:new(MockedModules, [])
     end,
     fun(_) ->
             meck:unload()
     end,
    [{"Simple success test",
      fun() -> meck:expect(ibrowse, send_req,
                           fun(_Url, _Headers, get) ->
                                    {ok, "200", [], make_response_body()}
                            end),
               ConfigList = pushy_client_config:get_config(OrgName, Hostname, Port),
               ?assertEqual("tcp://localhost:10000", proplists:get_value(heartbeat_address, ConfigList)),
               ?assertEqual("tcp://localhost:10002", proplists:get_value(command_address, ConfigList)),
               ?assertEqual(proplists:get_value(public_key, ConfigList), <<"-----BEGIN PUBLIC KEY-----\n">>)
               end},
     {"404 test",
      fun() -> meck:expect(ibrowse, send_req,
                           fun(_Url, _Headers, get) ->
                               {ok, "404", [], []}
                           end),

               ?assertThrow({error, {not_found, {"404", [], []}}}, pushy_client_config:get_config(OrgName, Hostname, Port))
      end},
     {"500 test",
      fun() -> meck:expect(ibrowse, send_req,
                           fun(_Url, _Headers, get) ->
                               {ok, "500", [], []}
                           end),
               ?assertThrow({error, {server_error, {"500", [], []}}}, pushy_client_config:get_config(OrgName, Hostname, Port))
      end},
     {"403 test",
      fun() -> meck:expect(ibrowse, send_req,
                           fun(_Url, _Headers, get) ->
                               {ok, "403", [], []}
                           end),
               ?assertThrow({error, {client_error, {"403",[], []}}}, pushy_client_config:get_config(OrgName, Hostname, Port))
      end}
    ]}.
