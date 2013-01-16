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
    PrivateKey = mk_private_key(),
    {foreach,
     fun() ->
             folsom:start()
     end,
     fun(_) ->
              folsom:stop()
     end,
     [{"Make a simple HMAC message",
      fun() ->
              [Header, Msg] = pushy_messaging:make_message(proto_v2, hmac_sha256, Hmac_sha256_key, EJson),
              ?assertMatch(<<"Version:2.0;SigningMethod:hmac_sha256;Signature:",_/binary>>, Header),
              <<"Version:2.0;SigningMethod:hmac_sha256;Signature:",Sig/binary>> = Header,
              ?assertEqual(<<"3OX7zAxVgH8Z8YGWL6ZYBN4n+AIPGNTqbHTB0Og7GMI=">>, Sig),
              ?assertEqual(JSon, Msg)
      end},
      {"Make a simple RSA2048 SHA1 message",
      fun() ->
              [Header, Msg] = pushy_messaging:make_message(proto_v2, rsa2048_sha1,
                                                           PrivateKey, EJson),
              ?assertMatch(<<"Version:2.0;SigningMethod:rsa2048_sha1;Signature:",_/binary>>, Header),
              <<"Version:2.0;SigningMethod:rsa2048_sha1;Signature:",Sig/binary>> = Header,
              ?assertEqual(<<"4rw5Z2Eqn3SZnLKMCIVyuj6/PZAHOQI1lSvQqheZv5AvR2JflVEtqQBi0GhLOz9V2J4uIHHwSukgt35QQHFE/lTs0wB/849EE3CGMqjTdzxVMnYUiK4ImKP7Jr+cvfD7Ff3nuhbZF9DBCnn4EAOUp8L0U/NpAgnmb5qxx8byc0mOskpYWiQQWVU2ck8jXYqDalDTHOR4Cn6cFRRHXfrE6pqv7srRUz2PkddspOZbdW9WUp7cYE5ACxpR62LQXQob6aZow88lDdP+ashcW3AJqCz1/eDpvkswsL2ssmSN5R63C2meBj/TRpg/4eWMAFmSm+/ByabpS2YxZygc9IU28w==">>, Sig),
              ?assertEqual(JSon, Msg)
      end}
     ]}.



parse_hmac_message_test_() ->
    EJsonNTS = mk_ejson_blob(),
    EJson = pushy_messaging:insert_timestamp_and_sequence(EJsonNTS, 0),
    Hmac_sha256_key = <<"01234567890123456789012345678901">>,
    KeyFetch = fun(hmac_sha256, _) -> {ok, Hmac_sha256_key} end,

    {foreach,
     fun() ->
             folsom:start()
     end,
     fun(_) ->
              folsom:stop()
     end,
     [{"parse a simple HMAC signed message",
       fun() ->
               [Header, Body] = mk_v2_hmac_msg(),
               {ok, R} = pushy_messaging:parse_message(Header, Body, KeyFetch),
               %% time might have changed, rip it out.
               BodyWOTimestamp = ej:delete({<<"timestamp">>}, R#pushy_message.body),
               EJsonStripped = ej:delete({<<"timestamp">>}, EJson),
               ?assertEqual(EJsonStripped, BodyWOTimestamp)
       end},
      {"parse a message whose body doesn't match header sig",
       fun() ->
               [Header, _Body] = mk_v2_hmac_msg(),
               {error, R} = (catch pushy_messaging:parse_message(Header, jiffy:encode(mk_ejson_med_blob()), KeyFetch)),
               ?assertMatch(#pushy_message{validated = bad_sig}, R)
       end}
     ]}.

parse_rsa_message_test_() ->
    EJsonNTS = mk_ejson_blob(),
    EJson = pushy_messaging:insert_timestamp_and_sequence(EJsonNTS, 0),
%    JSon = jiffy:encode(EJson),
    Key = mk_public_key(),
    KeyFetch = fun(rsa2048_sha1, _) -> {ok,Key} end,

    {foreach,
     fun() ->
             folsom:start()
     end,
     fun(_) ->
             folsom:stop()
     end,
     [{"parse a simple HMAC signed message",
       fun() ->
               [Header, Body] = mk_v2_rsa_msg(),
               {ok, R} = pushy_messaging:parse_message(Header, Body, KeyFetch),
               ?assertMatch({pushy_header, proto_v2, rsa2048_sha1, _}, R#pushy_message.parsed_header),
               ?assertEqual(EJson, R#pushy_message.body)
       end},
      {"parse a message whose body doesn't match header sig",
       fun() ->
               [Header, _Body] = mk_v2_rsa_msg(),
               {error, R} = (catch pushy_messaging:parse_message(Header, jiffy:encode(mk_ejson_med_blob()), KeyFetch)),
               ?assertMatch(#pushy_message{validated = bad_sig}, R)
       end}
     ]}.

parse_bad_message_test_() ->
    Hmac_sha256_key = <<"01234567890123456789012345678901">>,
    KeyFetch = fun(hmac_sha256, _) -> {ok, Hmac_sha256_key} end,

    {foreach,
     fun() ->
             folsom:start()
     end,
     fun(_) ->
              folsom:stop()
     end,
     [{"parse an empty header",
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
               [Header, Body] = mk_v2_hmac_msg(),
               {ok, R} = (pushy_messaging:parse_message(<<Header/binary,";asdfasdfasd:fooaste">>, Body, KeyFetch)),
               ?assertMatch(#pushy_message{validated = ok}, R)
       end},
      {"parse an empty body",
       fun() ->
               [Header, _Body] = mk_v2_hmac_msg(),
               {error, R} = (catch pushy_messaging:parse_message(Header, <<"">>, KeyFetch)),
               ?assertMatch(#pushy_message{validated = parse_fail}, R)
       end},
      {"parse a body that isn't json",
       fun() ->
               [Header, _Body] = mk_v2_hmac_msg(),
               {error, R} = (catch pushy_messaging:parse_message(Header, <<"asdfasd">>, KeyFetch)),
               ?assertMatch(#pushy_message{validated = parse_fail}, R)
       end},
      {"parse a message whose body doesn't match header sig (short)",
       fun() ->
               [Header, _Body] = mk_v2_hmac_msg(),
               {error, R} = (catch pushy_messaging:parse_message(Header, <<"{}">>, KeyFetch)),
               ?assertMatch(#pushy_message{validated = bad_sig}, R)
       end}
     ]}.

parse_bad_timestamp_test_() ->
    Hmac_sha256_key = <<"01234567890123456789012345678901">>,
    KeyFetch = fun(hmac_sha256, _) -> {ok, Hmac_sha256_key} end,

    {foreach,
     fun() ->
             folsom:start()
     end,
     fun(_) ->
              folsom:stop()
     end,
     [{"parse an message missing a timestamp",
       fun() ->
               [Header, Body] = mk_v2_hmac_msg(fun(M) -> ej:delete({"timestamp"}, M) end, Hmac_sha256_key),
               {error, R} = pushy_messaging:parse_message(Header, Body, KeyFetch),
               ?assertMatch(#pushy_message{validated = bad_timestamp}, R)
       end},
      {"parse an message with garbage for a timestamp",
       fun() ->
               [Header, Body] = mk_v2_hmac_msg(fun(M) -> ej:set({"timestamp"}, M, <<"garbage">>) end, Hmac_sha256_key),
               {error, R} = pushy_messaging:parse_message(Header, Body, KeyFetch),
               ?assertMatch(#pushy_message{validated = bad_timestamp}, R)
       end},
      {"parse an message with too much skew for a timestamp",
       fun() ->
               Secs = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
               BadTime = rfc1123_date(calendar:gregorian_seconds_to_datetime(Secs+10000)),
               [Header, Body] = mk_v2_hmac_msg(fun(Msg) -> ej:set({"timestamp"}, Msg, BadTime) end, Hmac_sha256_key),
               {error, R} = pushy_messaging:parse_message(Header, Body, KeyFetch),
               ?assertMatch(#pushy_message{validated = bad_timestamp}, R)
       end},
      {"parse an message with an old, but ok timestamp",
       fun() ->
               Secs = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
               OkTime = rfc1123_date(calendar:gregorian_seconds_to_datetime(Secs+1)),
               [Header, Body] = mk_v2_hmac_msg(fun(Msg) -> ej:set({"timestamp"}, Msg, OkTime) end, Hmac_sha256_key),
               {ok, R} = pushy_messaging:parse_message(Header, Body, KeyFetch),
               ?assertMatch(#pushy_message{validated = ok}, R)
       end}
     ]}.

timestamp_test_() ->
    {foreach,
     fun() ->
             ok
     end,
     fun(_) ->
             ok
     end,
     [{"add timestamp and sequence number",
      fun() ->
              SeqNo = 10,
              MsgBase = {[]},
              Msg = pushy_messaging:insert_timestamp_and_sequence(MsgBase, SeqNo),
              Time = ej:get({<<"timestamp">>}, Msg),
              MsgDate = httpd_util:convert_request_date(binary_to_list(Time)),
              MsgSecs = calendar:datetime_to_gregorian_seconds(MsgDate),
              NowSecs = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
              ?assert(abs(NowSecs - MsgSecs) < 1)
      end},
      {"check that we can validate a sane message",
       fun() ->
               SeqNo = 10,
               CurSeqNo = 9,
               MsgBase = {[]},
               Msg = pushy_messaging:insert_timestamp_and_sequence(MsgBase, SeqNo),

               Msg2 = jiffy:decode(jiffy:encode(Msg)),

               ?assertEqual(ok, pushy_messaging:check_seq(Msg2, CurSeqNo)),
               ?assertEqual(ok, pushy_messaging:check_timestamp(Msg2, 5))
       end},
      {"check that we fail to validate a message with an old sequence number",
       fun() ->
               SeqNo = 10,
               CurSeqNo = 10,
               MsgBase = {[]},
               Msg = pushy_messaging:insert_timestamp_and_sequence(MsgBase, SeqNo),
               Msg2 = jiffy:decode(jiffy:encode(Msg)),

               ?assertEqual(error, pushy_messaging:check_seq(Msg2, CurSeqNo)),
               ?assertEqual(ok, pushy_messaging:check_timestamp(Msg2, 5))
       end},
      {"check that we fail to validate a message with garbage instead of a sequence number",
       fun() ->
               SeqNo = 10,
               CurSeqNo = 10,
               MsgBase = {[]},
               Msg = pushy_messaging:insert_timestamp_and_sequence(MsgBase, SeqNo),
               Msg1 = ej:set({<<"sequence">>}, Msg, <<"Naughty">>),
               Msg2 = jiffy:decode(jiffy:encode(Msg1)),

               ?assertEqual(error, pushy_messaging:check_seq(Msg2, CurSeqNo)),
               ?assertEqual(ok, pushy_messaging:check_timestamp(Msg2, 5))
       end},
      {"check that we fail to validate a message without a sequence number",
       fun() ->
               SeqNo = 10,
               CurSeqNo = 10,
               MsgBase = {[]},
               Msg = pushy_messaging:insert_timestamp_and_sequence(MsgBase, SeqNo),
               Msg1 = ej:delete({<<"sequence">>}, Msg),
               Msg2 = jiffy:decode(jiffy:encode(Msg1)),

               ?assertEqual(error, pushy_messaging:check_seq(Msg2, CurSeqNo)),
               ?assertEqual(ok, pushy_messaging:check_timestamp(Msg2, 5))
       end},
      {"check that we validate a old (not expired) message",
       fun() ->
               SeqNo = 10,
               CurSeqNo = 9,
               MsgBase = {[]},

               Msg = pushy_messaging:insert_timestamp_and_sequence(MsgBase, SeqNo),
               NowSecs = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
               Date = rfc1123_date(calendar:gregorian_seconds_to_datetime(NowSecs-4)),
               Msg1 = ej:set({<<"timestamp">>}, Msg, Date),
               Msg2 = jiffy:decode(jiffy:encode(Msg1)),

               ?assertEqual(ok, pushy_messaging:check_seq(Msg2, CurSeqNo)),
               ?assertEqual(ok, pushy_messaging:check_timestamp(Msg2, 5))
       end},
      {"check that we fail to validate a old (expired) message",
       fun() ->
               SeqNo = 10,
               CurSeqNo = 9,
               MsgBase = {[]},

               Msg = pushy_messaging:insert_timestamp_and_sequence(MsgBase, SeqNo),
               NowSecs = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
               Date = rfc1123_date(calendar:gregorian_seconds_to_datetime(NowSecs-6)),
               Msg1 = ej:set({<<"timestamp">>}, Msg, Date),
               Msg2 = jiffy:decode(jiffy:encode(Msg1)),

               ?assertEqual(ok, pushy_messaging:check_seq(Msg2, CurSeqNo)),
               ?assertEqual(error, pushy_messaging:check_timestamp(Msg2, 5))
       end},
      {"check that we fail to validate a future message",
       fun() ->
               SeqNo = 10,
               CurSeqNo = 9,
               MsgBase = {[]},

               Msg = pushy_messaging:insert_timestamp_and_sequence(MsgBase, SeqNo),
               Date = rfc1123_date({{2112,12,21},{0,25,56}}),
               Msg1 = ej:set({<<"timestamp">>}, Msg, Date),
               Msg2 = jiffy:decode(jiffy:encode(Msg1)),

               ?assertEqual(ok, pushy_messaging:check_seq(Msg2, CurSeqNo)),
               ?assertEqual(error, pushy_messaging:check_timestamp(Msg2, 5))
       end},
      {"check that we fail to validate a message missing a timestamp",
       fun() ->
               SeqNo = 10,
               CurSeqNo = 9,
               MsgBase = {[]},

               Msg = pushy_messaging:insert_timestamp_and_sequence(MsgBase, SeqNo),
               Msg1 = ej:delete({<<"timestamp">>}, Msg),
               Msg2 = jiffy:decode(jiffy:encode(Msg1)),

               ?assertEqual(ok, pushy_messaging:check_seq(Msg2, CurSeqNo)),
               ?assertEqual(error, pushy_messaging:check_timestamp(Msg2, 5))
       end},
      {"check that we fail to validate a message with a garbage timestamp",
       fun() ->
               SeqNo = 10,
               CurSeqNo = 9,
               MsgBase = {[]},

               Msg = pushy_messaging:insert_timestamp_and_sequence(MsgBase, SeqNo),
               Msg1 = ej:set({<<"timestamp">>}, Msg, <<"naughty">>),
               Msg2 = jiffy:decode(jiffy:encode(Msg1)),

               ?assertEqual(ok, pushy_messaging:check_seq(Msg2, CurSeqNo)),
               ?assertEqual(error, pushy_messaging:check_timestamp(Msg2, 5))
       end}


     ]}.

%%
%% httpd_util:rfc1123_date expects time as local time, which makes life more complicated.
%% This is a copy that does
%%
rfc1123_date({{YYYY,MM,DD},{Hour,Min,Sec}}) ->
    DayNumber = calendar:day_of_the_week({YYYY,MM,DD}),
    lists:flatten(
      io_lib:format("~s, ~2.2.0w ~3.s ~4.4.0w ~2.2.0w:~2.2.0w:~2.2.0w GMT",
		    [httpd_util:day(DayNumber),DD,httpd_util:month(MM),YYYY,Hour,Min,Sec])).

mk_hmac_key() ->
    <<"01234567890123456789012345678901">>.

mk_v2_hmac_msg() ->
    Key = mk_hmac_key(),
    mk_v2_hmac_msg(fun(X) -> X end, Key).

mk_v2_hmac_msg(F, Key) ->
    EJson = mk_ejson_blob(),
    EJson2 = pushy_messaging:insert_timestamp_and_sequence(EJson, 0),
    EJson3 = F(EJson2),
    pushy_messaging:make_message(proto_v2, hmac_sha256, Key, EJson3).

mk_v2_rsa_msg() ->
    Key = mk_private_key(),
    mk_v2_rsa_msg(fun(X) -> X end, Key).

mk_v2_rsa_msg(F, Key) ->
    EJson = mk_ejson_blob(),
    EJson2 = pushy_messaging:insert_timestamp_and_sequence(EJson, 0),
    EJson3 = F(EJson2),
    pushy_messaging:make_message(proto_v2, rsa2048_sha1, Key, EJson3).
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

mk_private_key() ->
    {'RSAPrivateKey','two-prime',
     28704024528804691260855190679015202184345754631773777572759938135080025924815364302578785447032364276548474423405770571021079256371505117687580078450772230301622681079332742070079071876495531028870974202509684936349983807829303595135398805719586774883816776613883950868146576134430715146564466614543520928923138841559766608299980382532038922463523949572644066235020698636915792375482328322043520631652755837873559101935337881066775864083355154780237586740128862921908871198654820972751179366534169778832551707484570723835372794167575001910921676571865354645884964358835897131897263345446067436370109949030051058281931,
     65537,
     18812639662873611909722950474323511595346189155722402125253789809055836451906470282262944158359112299473375679517647486718470746279586482750730535570685560952524513181875570595787209886188146303356805391159169584677981209052780525838088177702266059502030639270887549653470556856465851468489304278415061025985642128448214495426606179882614436797058243913639680091121462549508700258420007819269531723990969354288508397352033780267865048797467029392730723495563379617607374771927587603550689642762005831288367941792416046138989248021961429319591040907221186787898038697445775924699607093757789034219657185457468248123889,
     169947842063941540295169123653984804884941900726673594737347880035478568799129961491376688942435634844462893534170016427855285406017229442243275073201422942240423552374581207169190980831199022268440080638748387005959977847955300565815438641128381803119461469684320193702240962529171739018740866908529116605369,
     168899023254470201272780959734032148690782137770680789380566525111829909491569080840195985752804812439242767727402636193525106811819877580878547326165742077330205371519028470121798244905038687438654271102345270831439721364313059356932232670649087979811256105120104939102103376011575465105573143227239899041699,
     167269109121450251235173858311742006107974004981512024580586350516631972806492195798400322619937870058245487045914563371261689272162829667858770088984613050128572879783480876256793796291189125721401024787857636990287050232761778959936509973104431692454914668668345969064335429558595813871017301357519601713729,
     88399002039330185602906140040542544398469843106521838908445799744585161442701238108237522427132121877389355262182245511300558291533540151391047070125442406495618878625420686843276341585481972287917972337481806228378074713784614019594008160824181253269235632722351030961765840678899705946049779297763946732827,
     98379581870630871054161017293428850704791832607784473237474347861802712668710816428714380392642997397100573527905714198327034480914931989459572504493969107008299627542889749148036394368517764174149596529815799774271076476993963454135110111454745716303464539918586979730725705063275703034488048850043330947150,
     asn1_NOVALUE}.

mk_public_key() ->
    {'RSAPublicKey',28704024528804691260855190679015202184345754631773777572759938135080025924815364302578785447032364276548474423405770571021079256371505117687580078450772230301622681079332742070079071876495531028870974202509684936349983807829303595135398805719586774883816776613883950868146576134430715146564466614543520928923138841559766608299980382532038922463523949572644066235020698636915792375482328322043520631652755837873559101935337881066775864083355154780237586740128862921908871198654820972751179366534169778832551707484570723835372794167575001910921676571865354645884964358835897131897263345446067436370109949030051058281931,
     65537}.
