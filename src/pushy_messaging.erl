%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92-*-
%% ex: ts=4 sw=4 et
%% @author Mark Anderson <mark@opscode.com>

%% @doc General messaging utilities for ZeroMQ
%% @copyright Copyright 2012 Chef Software, Inc. All Rights Reserved.
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
%%

-module(pushy_messaging).

-export([
         receive_message_async/2,
         parse_message/3,
         parse_message/4,

         is_signature_valid/4,

         make_message/4,
         make_header/4,

         make_send_message_multi/7,
         send_message/2,
         send_message_multi/3,

         insert_timestamp_and_sequence/2,
         check_seq/2,
         check_timestamp/2,
         get_max_message_skew/0,
         method_to_atom/1
        ]).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlzmq/include/erlzmq.hrl").

-include("pushy_messaging.hrl").
-include("pushy_metrics.hrl").

-define(MAX_HEADER_SIZE, 2048).
-define(MAX_BODY_SIZE, 65536).
-define(MAX_TIME_SKEW_DEFAULT, 300). % 5 min in seconds

%% ZeroMQ can provide frames as messages to a process. While ZeroMQ guarantees that a
%% message is all or nothing, I don't know if there is any possibility of frames of
%% different messages being interleaved.
%%
%% List is accumulated in reverse
receive_frame_list(Socket, List) ->
    %% This clause should probably get a timeout. I b
    receive
        {zmq, Socket, Frame, [rcvmore]} ->
            receive_frame_list(Socket, [Frame | List]);
        {zmq, Socket, Frame, []} ->
            lists:reverse([Frame | List])

    end.


%%
%% Many gen_servers have a handle_info({zmq, Socket, Frame, [rcvmore]}) call which
%% immediately get a set of frames from zmq.
%%
receive_message_async(Socket, Frame) ->
    %% collect the full message
    receive_frame_list(Socket, [Frame]).



-spec parse_message(binary(), binary(), pushy_key_fetch_fn()) -> {ok| error, #pushy_message{}}.
parse_message(Header, Body, KeyFetch) ->
    parse_message(none, Header, Body, KeyFetch).

-spec parse_message(Address :: binary() | 'none',
                    Header :: binary(),
                    Body :: binary(),
                    KeyFetch :: pushy_key_fetch_fn()) -> {ok| error, #pushy_message{}}.
parse_message(Address, Header, Body, KeyFetch) ->
    Msg1 = build_message_record(Address, Header, Body),
    Msg2 = parse_body(Msg1),
    Msg3 = validate_signature(Msg2,KeyFetch),
    Msg4 = validate_timestamp(Msg3),
    finalize_msg(Msg4).

%%
%% Build a message record for the various parse and validation stages to process
%%
-spec build_message_record(Address::binary() | none, Header::binary(), Body::binary()) -> #pushy_message{}.

%% Complicate attempts to DOS using too large packets
build_message_record(_Address, Header, _Body) when size(Header) > ?MAX_HEADER_SIZE ->
    lager:error("Message rejected because header is too big ~s > ~s", [size(Header), ?MAX_HEADER_SIZE]),
    #pushy_message{validated = header_too_big};
build_message_record(_Address, _Header, Body) when size(Body) > ?MAX_BODY_SIZE ->
    lager:error("Message rejected because body is too big ~s > ~s", [size(Body), ?MAX_BODY_SIZE]),
    #pushy_message{validated = body_too_big};
build_message_record(Address, Header, Body) when is_binary(Header), is_binary(Body) ->
    Id = make_ref(),

    case parse_header(Header) of
        #pushy_header{version=unknown} ->
            #pushy_message{validated = bad_header};
        #pushy_header{version=no_version} ->
            #pushy_message{validated = bad_header};
        #pushy_header{} = HeaderRecord ->
            #pushy_message{validated = ok_sofar,
                           id = Id,
                           address = Address,
                           header = Header,
                           raw = Body,
                           parsed_header = HeaderRecord
                          }
    end;
build_message_record(A,H,B) ->
    #pushy_message{validated = bad_input,
                  address = A,
                  header = H,
                  raw = B}.

len_h(none) -> 0;
len_h(B) when is_binary(B) -> erlang:byte_size(B).


%%
%% Parse various portions of the header
%%
parse_part(<<"Version:","1.0">>, Record) ->
    Record#pushy_header{version = proto_v1};
parse_part(<<"Version:","2.0">>, Record) ->
    Record#pushy_header{version = proto_v2};
parse_part(<<"Version:",_/binary>>, Record) ->
    Record#pushy_header{version = unknown};
parse_part(<<"SigningMethod:","hmac_sha256">>, Record) ->
    Record#pushy_header{method = hmac_sha256};
parse_part(<<"SigningMethod:","rsa2048_sha1">>, Record) ->
    Record#pushy_header{method = rsa2048_sha1};
parse_part(<<"SigningMethod:",_>>, Record) ->
    Record#pushy_header{method = unknown};
parse_part(<<"Signature:",Signature/binary>>, Record) ->
    Record#pushy_header{signature = Signature};
parse_part(<<"SignedChecksum:",Signature/binary>>, Record) ->
    Record#pushy_header{signature = Signature};
%% We are generous what we accept, in that they ignore unknown fields
parse_part(_, Record) ->
    Record.

parse_header(Header) ->
    HeaderParts = re:split(Header, <<";">>),
    lists:foldl(fun parse_part/2, #pushy_header{version=no_version, method=unknown, signature = <<>>}, HeaderParts).

%%
%% Parse the json body of the message
%%
parse_body(#pushy_message{validated = ok_sofar,
                          id = Id,
                          raw=Raw} = Message) ->
    try jiffy:decode(Raw) of
        {error, Error} ->
            lager:error("JSON parsing of msg id ~s failed with error: ~w", [Id, Error]),
            Message#pushy_message{validated = parse_fail};
        Data ->
            Message#pushy_message{body = Data}
    catch
        throw:Error ->
            lager:error("JSON parsing failed with throw: ~w", [Error]),
            Message#pushy_message{validated = parse_fail}
    end;
parse_body(Message) -> Message.

% TODO - update chef_authn to export this function
decrypt_sig(Sig, {'RSAPublicKey', _, _} = PK) ->
    try
        public_key:decrypt_public(base64:decode(Sig), PK)
    catch
        error:decrypt_failed ->
            decrypt_failed
    end.

is_signature_valid(#pushy_header{version=unknown}, _, _, _) ->
    lager:error("Unknown header type~n",[]),
    false;
is_signature_valid(#pushy_header{version=Proto, method=rsa2048_sha1=M, signature=Sig}, Body, EJson, KeyFetch)
  when Proto =:= proto_v1 orelse Proto =:= proto_v2 ->
    true;
is_signature_valid(#pushy_header{version=proto_v2, method=hmac_sha256=M, signature=Sig}, Body, EJson, KeyFetch) ->
    true;
is_signature_valid(Signature, _, _, _) ->
    lager:error("Can't handle signature ~w~n",[Signature]),
    false.

%%
%% We leak information if we early out a string compare at first difference; this could be used
%% to compute a valid signature for a term.
%% Alternately we could compute the sha of each and compare, which converts a timing attack into
%% a preimage attack. Computing the sha would take about 12ms on a modern processor...
%%
%% It's ok to quit early if they are diffent lengths
compare_in_constant_time(<<Bin1/binary>>, <<Bin2/binary>>) when
      byte_size(Bin1) /= byte_size(Bin2) ->
    1;
compare_in_constant_time(<<Bin1/binary>>, <<Bin2/binary>>) ->
    compare_in_constant_time(Bin1, Bin2, 0).

compare_in_constant_time(<<H1,T1/binary>>, <<H2, T2/binary>>, Acc) ->
    compare_in_constant_time(T1, T2, (H1 bxor H2) bor Acc);
compare_in_constant_time(<<>>, <<>>, Acc) ->
    Acc.



validate_signature(#pushy_message{validated = ok_sofar,
                                  parsed_header = Header,
                                  raw = Raw, body = EJson} = Message,
                   KeyFetch) ->
    case is_signature_valid(Header, Raw, EJson, KeyFetch) of
        true -> Message#pushy_message{validated = ok_sofar};
        _Else ->

            Message#pushy_message{validated=bad_sig}
    end;
validate_signature(#pushy_message{} = Message, _KeyFetch) -> Message.

%%
%%
validate_timestamp(#pushy_message{validated = ok_sofar,
                                  body = EJson} = Message) ->
    case check_timestamp(EJson, get_max_message_skew()) of
        ok ->
            Message#pushy_message{validated = ok_sofar};
        _Else ->
            Message#pushy_message{validated = bad_timestamp}
    end;
validate_timestamp(#pushy_message{} = Message) ->
                          Message.

get_max_message_skew() ->
    envy:get(pushy_common, max_time_skew, ?MAX_TIME_SKEW_DEFAULT, integer). %% expect seconds

%%
-spec finalize_msg(Message :: #pushy_message{}) -> {ok| error, #pushy_message{}}.
finalize_msg(#pushy_message{validated = ok_sofar} = Message) ->
    {ok, Message#pushy_message{validated = ok}};
finalize_msg(#pushy_message{} = Message) ->
    {error, Message}.

%%
%% Message generation
%%
-spec make_message(Proto :: pushy_message_version(),
                   Method :: pushy_signing_method(),
                   Key :: tuple(),
                   EJson :: any()) -> [ binary()].
make_message(Proto, Method, Key, EJson) ->
    Json = jiffy:encode(EJson),
    Header = make_header(Proto, Method, Key, Json),
    [Header, Json].

-spec make_header(Proto:: pushy_message_version(),
                  Algorithm:: pushy_signing_method(),
                  Key:: tuple(),
                  Body:: any()) -> binary().
make_header(Proto, hmac_sha256, Key, Body) ->
    create_headers(Proto, hmac_sha256, <<"xxx">>);
make_header(Proto, rsa2048_sha1, Key, Body) ->
    create_headers(Proto, rsa2048_sha1, <<"xxx">>).

create_headers(Proto, Method, Sig) ->
    Headers = [join_bins(tuple_to_list(Part), <<":">>) || Part <- [{<<"Version">>, proto_to_bin(Proto)},
                                                                   {<<"SigningMethod">>, atom_to_binary(Method, utf8)},
                                                                   {<<"Signature">>, Sig}]],
    join_bins(Headers, <<";">>).

join_bins([], _Sep) ->
    <<>>;
join_bins(Bins, Sep) when is_binary(Sep) ->
    join_bins(Bins, Sep, []).

join_bins([B], _Sep, Acc) ->
    iolist_to_binary(lists:reverse([B|Acc]));
join_bins([B|Rest], Sep, Acc) ->
    join_bins(Rest, Sep, [Sep, B | Acc]).


proto_to_bin(proto_v1) ->
    <<"1.0">>;
proto_to_bin(proto_v2) ->
    <<"2.0">>.

method_to_atom(<<"hmac_sha256">>) ->
    hmac_sha256;
method_to_atom(<<"rsa2048_sha1">>) ->
    rsa2048_sha1.

%%%
%%% Bulk message generation
%%%
make_send_message_multi(Socket, Proto, rsa2048_sha1 = Method, NameList, EJson, NameToAddrF, NameToKeyF) ->
    make_send_message_multi_pub_key(Socket, Proto, Method, NameList, EJson, NameToAddrF, NameToKeyF);
make_send_message_multi(Socket, Proto, hmac_sha256 = Method, NameList, EJson, NameToAddrF, NameToKeyF) ->
    make_send_message_multi_priv_key(Socket, Proto, Method, NameList, EJson, NameToAddrF, NameToKeyF).

%%
%% With pubkey methods we only have to sign once
%%
make_send_message_multi_pub_key(Socket, Proto, Method, NameList, EJson, NameToAddrF, NameToKeyF) when
      is_function(NameToAddrF) andalso is_function(NameToKeyF) ->
    Key = NameToKeyF(Method, any),
    make_send_message_multi_pub_key(Socket, Proto, Method, NameList, EJson, NameToAddrF, Key);
make_send_message_multi_pub_key(Socket, Proto, Method, NameList, EJson, NameToAddrF, Key) ->
    Json = jiffy:encode(EJson),
    Header = make_header(Proto, Method, Key, Json),
    [send_message(Socket,
                  [ NameToAddrF(Name), Header, Json ]) ||
     Name <- NameList].

%%
%% Private key methods need a different sign for each recipient
%%
make_send_message_multi_priv_key(Socket, Proto, Method, NameList, EJson, NameToAddrF, NameToKeyF) when
      is_function(NameToAddrF) andalso is_function(NameToKeyF) ->
    Json = jiffy:encode(EJson),
    [send_message(Socket,
                  [ NameToAddrF(Name), make_header(Proto, Method, NameToKeyF(Method, Name), Json),  Json ]) ||
        Name <- NameList].

%%%
%%% Low level transmission routines.
%%%
send_message(_Socket, []) ->
    ok;
send_message(Socket, [Frame | [] ]) ->
    erlzmq:send(Socket, Frame, []);
send_message(Socket, [ Frame | FrameList]) ->
    erlzmq:send(Socket, Frame, [sndmore]),
    send_message(Socket, FrameList).

send_message_multi(Socket, AddressList, FrameList) ->
    [ send_message(Socket, [Address | FrameList] ) || Address <- AddressList ].

metric_name(Name) ->
    pushy_metrics:app_metric(?MODULE, Name).


%%%
%%% Utility routines for timestamps and sequence numbering
%%%
%%% Note: we use RFC 1123 dates for human readability. If we move to a binary format we should
%%% change this to a raw seconds value or the like.
-spec insert_timestamp_and_sequence({json_plist()}, pos_integer()) -> {json_plist()}.
insert_timestamp_and_sequence({Fields}, Sequence) ->
    {[{<<"sequence">>, Sequence},
      {<<"timestamp">>, list_to_binary(httpd_util:rfc1123_date())} |
      Fields]}.

check_seq(Msg, LastSeq) when is_integer(LastSeq) ->
    case ej:get({<<"sequence">>}, Msg) of
        CurSeq when is_integer(CurSeq) andalso LastSeq < CurSeq ->
            ok;
        _ ->
            error
    end;
check_seq(_, _) ->
    error.

check_timestamp(Message, MaxTimeSkew) ->
    compare_time(ej:get({<<"timestamp">>}, Message), MaxTimeSkew).

compare_time(MsgTime, MaxTimeSkew) when is_binary(MsgTime) ->
    compare_time(binary_to_list(MsgTime), MaxTimeSkew);
compare_time(MsgTime, MaxTimeSkew) when is_list(MsgTime) andalso is_integer(MaxTimeSkew) ->
    case httpd_util:convert_request_date(MsgTime) of
        bad_date ->
            error;
        EDate ->
            NowSecs = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
            MsgSecs = calendar:datetime_to_gregorian_seconds(EDate),
            case abs(NowSecs - MsgSecs) of
                N when N < MaxTimeSkew ->
                    ok;
                _ ->
                    error
            end
    end;
compare_time(_, _) ->
    error.
