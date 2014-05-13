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

-include_lib("ej/include/ej.hrl").

-type pushy_message_version() :: 'proto_v1' | 'proto_v2' | 'no_version' | 'unknown'.
-type pushy_signing_method() :: 'rsa2048_sha1' | 'hmac_sha256' | 'unknown'.
-type pushy_validation_states() :: 'ok_sofar' |
                                   'ok' |
                                   'bad_input' |
                                   'header_too_big' |
                                   'body_too_big' |
                                   'bad_header' |
                                   'bad_sig' |
                                   'bad_timestamp' |
                                   'parse_fail'.

-type pushy_key_fetch_fn() :: any(). %% fun((pushy_signing_method(), json_term()) -> {ok, any()} | {fail, any()}.


-record(pushy_header,
        {version :: pushy_message_version(),
         method :: pushy_signing_method(),
         signature :: binary()}).

-record(pushy_message,
        {validated :: pushy_validation_states(),
         id :: reference(),
         address :: binary() | 'none',
         header  :: binary() | 'none',
         raw  :: binary() | 'none',
         parsed_header :: #pushy_header{},

         body :: json_term()
        }).

