%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92-*-
%% ex: ts=4 sw=4 et
%% @author Mark Anderson <mark@opscode.com>
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


-module(pushy_messaging_tests).


-include_lib("eunit/include/eunit.hrl").
-include("pushy_client.hrl").
-include("pushy_messaging.hrl").

make_message_test_() ->
    EJson = mk_ejson_blob(),
    JSon = jiffy:encode(EJson),
    Hmac_sha256_key = mk_hmac_key(),
    {foreach,
     fun() ->
             ok
     end,
     fun(_) ->
             ok
     end,
     [{"Make a simple HMAC message",
      fun() ->
              [Header, Msg] = pushy_messaging:make_message(proto_v2, hmac_sha256,
                                                           {hmac_sha256, Hmac_sha256_key}, EJson),
              <<"Version:2.0;SigningMethod:hmac_sha256;Signature:",Sig/binary>> = Header,
              ?assertEqual(<<"3OX7zAxVgH8Z8YGWL6ZYBN4n+AIPGNTqbHTB0Og7GMI=">>, Sig),
              ?assertEqual(JSon, Msg)
      end}
     ]}.



parse_message_test_() ->
    EJson = mk_ejson_blob(),
%    JSon = jiffy:encode(EJson),
    Hmac_sha256_key = <<"01234567890123456789012345678901">>, 
    [Header, Body] = mk_v2_hmac_msg(),
    KeyFetch = fun(hmac_sha256, _) -> {ok, Hmac_sha256_key} end,

    {foreach,
     fun() ->
             ok
     end,
     fun(_) ->
             ok
     end,
     [{"parse a simple HMAC signed message",
       fun() ->
               {ok, R} = pushy_messaging:parse_message(Header, Body, KeyFetch),
               ?assertEqual({pushy_header, proto_v2, hmac_sha256, <<"3OX7zAxVgH8Z8YGWL6ZYBN4n+AIPGNTqbHTB0Og7GMI=">>}, R#pushy_message.parsed_header),
               ?assertEqual(EJson, R#pushy_message.body)
       end},
      {"parse an empty header",
       fun() ->
               {error, R} = pushy_messaging:parse_message(<<"">>, <<"">>, KeyFetch),
               ?assertMatch(#pushy_message{validated = bad_header}, R)
       end},
      {"parse a garbage header 1",
       fun() ->
               {error, R} = (pushy_messaging:parse_message(<<"asdfasdfasd">>, <<"">>, KeyFetch)),
               ?assertMatch(#pushy_message{validated = bad_header}, R)
       end},
      {"parse a broken header (ignore bad key)",
       fun() ->
               {ok, R} = (pushy_messaging:parse_message(<<Header/binary,";asdfasdfasd:fooaste">>, Body, KeyFetch)),
               ?assertMatch(#pushy_message{validated = ok}, R)
       end},
      {"parse an empty body",
       fun() ->
               {error, R} = (catch pushy_messaging:parse_message(Header, <<"">>, KeyFetch)),
               ?assertMatch(#pushy_message{validated = parse_fail}, R)
       end},
      {"parse a body that isn't json",
       fun() ->
               {error, R} = (catch pushy_messaging:parse_message(Header, <<"asdfasd">>, KeyFetch)),
               ?assertMatch(#pushy_message{validated = parse_fail}, R)
       end},
      {"parse a message whose body doesn't match header sig (short)",
       fun() ->
               {error, R} = (catch pushy_messaging:parse_message(Header, <<"{}">>, KeyFetch)),
               ?assertMatch(#pushy_message{validated = bad_sig}, R)
       end},
      {"parse a message whose body doesn't match header sig",
       fun() ->
               {error, R} = (catch pushy_messaging:parse_message(Header, jiffy:encode(mk_ejson_med_blob()), KeyFetch)),
               ?assertMatch(#pushy_message{validated = bad_sig}, R)
       end}
     ]}.

mk_hmac_key() ->
    <<"01234567890123456789012345678901">>.

mk_v2_hmac_msg() ->
    EJson = mk_ejson_blob(),
    Key = mk_hmac_key(),
    pushy_messaging:make_message(proto_v2, hmac_sha256,
                                 {hmac_sha256, Key}, EJson).
mk_ejson_blob() ->
    {[{<<"type">>,<<"config">>},
      {<<"host">>,<<"localhost">>},
      {<<"lifetime">>,3600}]}.
mk_ejson_med_blob() ->
    {[{<<"type">>,<<"config">>},
      {<<"host">>,<<"localhost">>},
      {<<"push_jobs">>,
       {[{<<"heartbeat">>,
          {[{<<"out_addr">>,<<"tcp://localhost:10000">>},
            {<<"command_addr">>,<<"tcp://localhost:10002">>},
            {<<"interval">>,1.0},
            {<<"offline_threshold">>,3},
            {<<"online_threshold">>,2}]}
         }]}
      },
      {<<"public_key">>,
       <<"-----BEGIN PUBLIC KEY-----\n\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx4Kc2bvqzVjWph8Iotkf\ns2uW7DyA7uL30DnmCK+yoiIBwC3R+TtxP\/kh1bv8T25aiK1OYwluA3LhEgVdgnPV\nyHPiuVY6t61+pR80Knxee3LReDYulf404YfUd0um5OS+MABOMB2V6inPLKDsRMlm\n1nw8QLtA5fBak5zIMEfx2QmwDsFWmOxS0WufJwASW3XbJzKvGhYpodelBLDAofe+\nzVJh9vBNqamh\/vpP\/OKCmsDaTV2Glb7KvG8Q25Ves1+OHpb8O8EqTovxcX+KQuLB\nvfW6Q3UO6Oil+FYFhyNSPg69NCiXISxg\/TaCGThqFxD97Nq+EQj\/61hsF9vfh2v6\nnwIDAQAB\n-----END PUBLIC KEY-----\n\n">>},
      {<<"lifetime">>,3600}]}.
