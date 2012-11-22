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
-include("pushy_client.hrl").

-define(GV(Config, Field), Config#pushy_client_config.Field).

setup_env() ->
    ok.

-define(ORG_NAME, <<"ponyville">>).
-define(HOST_NAME, <<"localhost">>).

make_response_body() ->
    jiffy:encode({[{<<"type">>,<<"config">>},
                   {<<"host">>, ?HOST_NAME},
                   {<<"push_jobs">>,{[{<<"heartbeat">>,{[{<<"out_addr">>,<<"tcp://localhost:10000">>},
                                                         {<<"command_addr">>,<<"tcp://localhost:10002">>},
                                                         {<<"interval">>,1.0},
                                                         {<<"offline_threshold">>,3},
                                                         {<<"online_threshold">>,2}]}}]}},
                   {<<"node">>,"private-chef-0001"},
                   {<<"organization">>, ?ORG_NAME},
                   {<<"public_key">>,<<"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArIdww4unGKp5GDNNgUtF\nX1D4R+B/DH5CctUk6nlG+WHvv/Ee0AtH/MDmIxr2Zsec/W6yKONdJMJVMeU7CORQ\n+DGFFQSa0IEo4bMOJALPPZ5qBXaA42HwtYj32SL4IbIzqTDPiNDVitJfC4vvURpO\n6e76E2g+bnLO/Viz/Ehf3/tCdFLC22olXDD8MNzhg6r/OLalCu2EP/c4wg/UnMNU\niqFQtQ1kgaUfYzpZ+eSaiUgZ1DpAsgH4hjKLyYSXVN9VifJailmoZmj5RTmPC7eJ\nct2oKay+WZWMS+uWodlK/8gWe5dOwqPQbYSJtD/MsFIDxnUf5+EpA0sy9uvdQxoM\nnwIDAQAB\n-----END PUBLIC KEY-----\n\n">>},
                   {<<"session_key">>,{[{<<"method">>,<<"hmac_sha256">>},
                                        {<<"key">>,<<"i3LtOYBsG8xTXvK/5D14qVpyfok5lPFApAS2c8jmBNE=">>}]}},
                   {<<"lifetime">>,3600}]}).

simple_test_() ->
    MockedModules = [ibrowse, chef_authn],
    %% request data
    OrgName = ?ORG_NAME,
    HostName = ?HOST_NAME,
    NodeName = ?HOST_NAME,
    CreatorName = <<"rainbowdash">>,
    CreatorKey = key,
    Port = 10002,

    {foreach,
     fun() ->
             setup_env(),
             meck:new(MockedModules, []),
             meck:expect(chef_authn, sign_request,
                         fun(_CreatorKey, <<"">>, _NodeName,
                             <<"GET">>, now, _Url) ->
                             []
                         end)
     end,
     fun(_) ->
             meck:unload()
     end,
    [{"Simple success test",
      fun() -> meck:expect(ibrowse, send_req,
                           fun(_Url, _Headers, get) ->
                                    {ok, "200", [], make_response_body()}
                            end),
               meck:expect(chef_authn, extract_public_or_private_key,
                           fun(_Key) -> {'RSAPublicKey', foo, bar} end),
               Config = pushy_client_config:get_config(OrgName, NodeName, CreatorName, CreatorKey, HostName, Port),
               ?assertEqual("tcp://localhost:10000", ?GV(Config,heartbeat_address)),
               ?assertEqual("tcp://localhost:10002", ?GV(Config, command_address))
               end},
     {"404 test",
      fun() -> meck:expect(ibrowse, send_req,
                           fun(_Url, _Headers, get) ->
                               {ok, "404", [], []}
                           end),

               ?assertThrow({error, {not_found, {"404", [], []}}}, pushy_client_config:get_config(OrgName, NodeName,
                                                                                                  CreatorName, CreatorKey,
                                                                                                  HostName, Port))
      end},
     {"500 test",
      fun() -> meck:expect(ibrowse, send_req,
                           fun(_Url, _Headers, get) ->
                               {ok, "500", [], []}
                           end),
               ?assertThrow({error, {server_error, {"500", [], []}}}, pushy_client_config:get_config(OrgName, NodeName,
                                                                                                     CreatorName, CreatorKey,
                                                                                                     HostName, Port))
      end},
     {"403 test",
      fun() -> meck:expect(ibrowse, send_req,
                           fun(_Url, _Headers, get) ->
                               {ok, "403", [], []}
                           end),
               ?assertThrow({error, {client_error, {"403",[], []}}}, pushy_client_config:get_config(OrgName, NodeName,
                                                                                                    CreatorName, CreatorKey,
                                                                                                    HostName, Port))
      end}
    ]}.
