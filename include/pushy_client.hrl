


-record(pushy_client_config, {command_address :: list(),
                              heartbeat_address :: list(),
                              heartbeat_interval :: integer(),
                              server_public_key :: {'RsaPublicKey', integer(), integer()}
                             }).

