%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92-*-
%% ex: ts=4 sw=4 et
%% @author Mark Anderson <mark@opscode.com>
%% @copyright 2012 Opscode, Inc.

%% @doc General messaging utilities for ZeroMQ
-module(pushy_messaging).

-export([
         receive_message_async/2,
         send_message/2,
         send_message_multi/3,

         parse_message/3,

         signed_header_from_message/3,
         make_message/4
        ]).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlzmq/include/erlzmq.hrl").

-include("pushy_messaging.hrl").
-include("pushy_metrics.hrl").

-define(MAX_HEADER_SIZE, 2048).
-define(MAX_BODY_SIZE, 65536).

%% ZeroMQ can provide frames as messages to a process. While ZeroMQ guarantees that a message is all or nothing, I don't
%% know if there is any possibility of frames of different messages being interleaved.
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
    Msg1 = build_message_record(none, Header, Body),
    Msg2 = parse_body(Msg1),
%    lager:error("Processed msg (2) ~p ~p", [Msg2#pushy_message.validated, Msg2#pushy_message.body]),
    Msg3 = validate_signature(Msg2,KeyFetch),
%    lager:error("Processed msg (3) ~p ~p", [Msg3#pushy_message.validated, Msg3#pushy_message.body]),
    finalize_msg(Msg3).


%%
%% Build a message record for the various parse and validation stages to process
%%
-spec build_message_record(Address::binary() | none, Header::binary(), Body::binary()) -> #pushy_message{}.

%% Complicate attempts to DOS using too large packets
build_message_record(_Address, Header, _Body) when size(Header) > ?MAX_HEADER_SIZE ->
    #pushy_message{validated = header_to_big};
build_message_record(_Address, _Header, Body) when size(Body) > ?MAX_BODY_SIZE ->
    #pushy_message{validated = body_to_big};
build_message_record(Address, Header, Body) when is_binary(Header), is_binary(Body) ->
    Id = make_ref(),
    lager:debug("Received msg ~w (~w:~w:~w)",[Id, len_h(Address), len_h(Header), len_h(Body)]),

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
                    raw=Raw} = Message) ->
    try jiffy:decode(Raw) of
        {error, Error} ->
            ?debugVal(Error),
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
    {ok, Key} = KeyFetch(M, EJson),
    Decrypted = decrypt_sig(Sig, Key),
    case chef_authn:hash_string(Body) of
        Decrypted -> true;
        _Else ->
            lager:error("Validation failed sig provided ~s expected ~s~n", [Decrypted, _Else]),
            pushy_util:get_env(pushy, ignore_signature_check, false, fun is_boolean/1)
    end;
is_signature_valid(#pushy_header{version=proto_v2, method=hmac_sha256=M, signature=Sig}, Body, EJson, KeyFetch) ->
    {ok, Key} = KeyFetch(M, EJson),
    HMAC = hmac:hmac256(Key, Body),
    ExpectedSignature = base64:encode(HMAC),
    case Sig of
        ExpectedSignature -> true;
        _Else ->
            lager:error("Validation failed sig provided ~s expected ~s~n", [ExpectedSignature, _Else]),
            pushy_util:get_env(pushy, ignore_signature_check, false, fun is_boolean/1)
    end;
is_signature_valid(Signature, _, _, _) ->
    lager:error("Can't handle signature ~w~n",[Signature]),
    false.



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


finalize_msg(#pushy_message{validated = ok_sofar} = Message) ->
    {ok, Message#pushy_message{validated = ok}};
finalize_msg(#pushy_message{} = Message) ->
    {error, Message}.

%%
%% Message generation
%%
-spec make_message(proto_v1| proto_v2, atom(), tuple(), any()) -> {binary(), binary()}.
make_message(Proto, rsa2048_sha1, Key, EJson) when Proto =:= proto_v1 orelse Proto =:= proto_v2 ->
    %% Only supports rsa2048_sha1
    Json = jiffy:encode(EJson),
    Header = signed_header_from_message(Proto, Key, Json),
    [Header, Json];
make_message(proto_v2, hmac_sha256, Key, EJson) ->
    Json = jiffy:encode(EJson),
    Header = signed_header_from_message(proto_v2, Key, Json),
    [Header, Json].

signed_header_from_message(Proto, {hmac_sha256, Key}, Body) ->
    HMAC = hmac:hmac256(Key, Body),
    SignedChecksum = base64:encode(HMAC),
    create_headers(Proto, hmac_sha256, SignedChecksum);
signed_header_from_message(Proto, PrivateKey, Body) ->
    %% TODO Find better way of enforcing this
    ['RSAPrivateKey' | _ ] = tuple_to_list(PrivateKey),
    HashedBody = chef_authn:hash_string(Body),
    SignedChecksum = base64:encode(public_key:encrypt_private(HashedBody, PrivateKey)),
    create_headers(Proto, rsa2048_sha1, SignedChecksum).

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

%%%
%%%
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
