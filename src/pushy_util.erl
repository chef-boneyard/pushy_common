%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92-*-
%% ex: ts=4 sw=4 et
%% @author Mark Anderson <mark@opscode.com>
%% @copyright 2012 Opscode, Inc.

%% @doc General utility module for common functions that operate on
-module(pushy_util).

-export([
         make_zmq_socket_addr/1,
         make_zmq_socket_addr/2,
         make_zmq_socket_addr/3,
         get_env/3, % deprecated
         get_env/4, % deprecated
         read_body/0,
         rand_bytes/1,
         guid_v4/0,
         gen_req_id_using_rand/2,
         gproc_match_head/3
        ]).

-include_lib("eunit/include/eunit.hrl").

make_zmq_socket_addr(Port) ->
    Host = envy:get(pushy, zeromq_listen_address, string),
    make_zmq_socket_addr(Host, Port).

make_zmq_socket_addr(Host, PortName, tcp) ->
    ProtoHost = io_lib:format("tcp://~s", [Host]),
    make_zmq_socket_addr(ProtoHost, PortName).


make_zmq_socket_addr(Host, PortName) when is_atom(PortName) ->
    Port = envy:get(pushy, PortName, integer),
    make_zmq_socket_addr(Host, Port);
make_zmq_socket_addr(Host, Port) when is_integer(Port) ->
    lists:flatten(io_lib:format("~s:~w",[Host,Port])).

%%
%% These are deprecated
%%
get_env(Section, Item, TypeCheck) ->
    envy:get(Section, Item, TypeCheck).

get_env(Section, Item, Default, TypeCheck) ->
    envy:get(Section, Item, Default, TypeCheck).

%%
%% Factor out common packet handling methods
%%

read_body() ->
    receive
        {zmq, _Sock, BodyFrame, []} ->
            BodyFrame
    end.

%%% R15 introduces strong_rand_bytes, which is preferable, but we still need to work on older versions.
-spec rand_bytes(non_neg_integer()) -> binary().
rand_bytes(NBytes) ->
    case lists:member(strong_rand_bytes, crypto:info()) of
        false -> crypto:rand_bytes(NBytes);
        true -> crypto:strong_rand_bytes(NBytes)
    end.

% RFC4122 V4 GUID
% Version 4 UUIDs have the form xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
% where x is any hexadecimal digit and
% y is one of 8, 9, A, or B
-spec guid_v4() -> string().
guid_v4() ->
    <<TL:32, TM:16, TH:12, CS:14, N:48, _:6>> = rand_bytes(16),
    THV = TH bor (4 bsl 12),
    CSV = CS bor (2 bsl 14), % see section 4.4 of RFV (set high order bits to '10XX_XXXX_XXXX_XXXX')
    lists:flatten(io_lib:format("~8.16.0b-~4.16.0b-~4.16.0b-~4.16.0b-~12.16.0b", [TL, TM, THV, CSV, N])).

-spec gen_req_id_using_rand(string() | binary(), non_neg_integer()) -> binary().
gen_req_id_using_rand(Prefix, NBytes) ->
    RandBytes = rand_bytes(NBytes),
    NBits = NBytes*8,
    <<RandValue:NBits, _/binary>> = RandBytes,
    iolist_to_binary([Prefix, integer_to_list(RandValue, 16)]).

%% MatchHead for gproc
-spec gproc_match_head(atom(), atom(), any()) -> {{atom(), atom(), any()}, '_', '_'}.
gproc_match_head(Type, Scope, Key) ->
    {{Type, Scope, Key}, '_', '_'}.


