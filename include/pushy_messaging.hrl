%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92-*-
%% ex: ts=4 sw=4 et
%% @author Mark Anderson <mark@opscode.com>
%% @copyright 2012 Opscode, Inc.

%% @doc General messaging utilities for ZeroMQ
-type json_term() :: any().


-type pushy_message_version() :: 'proto_v1' | 'proto_v2' | 'no_version' | 'unknown'.
-type pushy_signing_method() :: 'rsa2048_sha1' | 'hmac_sha256' | 'unknown'.
-type pushy_validation_states() :: 'ok_sofar' |
                                   'ok' |
                                   'bad_input' |
                                   'header_too_big' |
                                   'body_too_big' |
                                   'bad_header' |
                                   'bad_sig' |
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

         body :: json_term() % Get a viable json type here
        }).

