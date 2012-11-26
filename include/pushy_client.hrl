

-include_lib("public_key/include/public_key.hrl").

-record(pushy_client_config, {command_address :: list(),
                              heartbeat_address :: list(),
                              heartbeat_interval :: integer(),
                              session_method :: atom(),
                              session_key :: binary(),
                              server_public_key :: rsa_public_key()
                             }).

