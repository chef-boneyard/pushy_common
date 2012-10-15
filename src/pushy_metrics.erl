%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92-*-
%% ex: ts=4 sw=4 et
%% @author Seth Chisamore <schisamo@opscode.com>
%% @copyright 2012 Opscode, Inc.

%% HEAVILY INSPIRED by metrics logic in stats_hero AND pooler

%% @doc General metric module
-module(pushy_metrics).

-export([
         send/3,
         label/2,
         ctime/2
        ]).

%% type specs for metrics
-type metric_label() :: binary().
-type metric_value() :: non_neg_integer() |
                        {'inc',1}.
-type metric_type() :: 'counter' | 'histogram' | 'history' | 'meter'.

%% @doc Generate a folsom metric label for upstream `Prefix' and function name `Fun'.
%% An error is thrown if `Prefix' is unknown.
%% This is where we encode the mapping of module to upstream label.
label(pushy_client_config, get_config) ->
    label('config', get_config);
label(pushysim_client, connect_to_heartbeat) ->
    label('messaging', all);
label(pushysim_client, connect_to_command) ->
    label('messaging', all);
label(pushysim_client, receive_message) ->
    label('messaging', recv);
label(pushysim_client, send_heartbeat) ->
    label('messaging', heartbeat);
label(pushysim_client, send_response) ->
    label('messaging', send);
label(jiffy, encode) ->
    label('messaging', send);
label(jiffy, decode) ->
    label('messaging', recv);

label(pushy_heartbeat_generator, do_send) ->
    label(send, all);
label(pushy_command_switch, do_send) ->
    label(send, all);
label(pushy_command_switch, do_send_multi) ->
    label(send, all);
label(pushy_command_switch, do_receive) ->
    label('receive', all);
label(pushy_messaging, _) ->
    label('messaging', all);
label(chef_authn, _) ->
    label('authn', all);
label(authn, _) ->
    label('authn', all);
label(Prefix, Fun) when Prefix =:= send;
                        Prefix =:= 'receive';
                        Prefix =:= 'config';
                        Prefix =:= 'messaging' ->
    PrefixBin = erlang:atom_to_binary(Prefix, utf8),
    FunBin = erlang:atom_to_binary(Fun, utf8),
    iolist_to_binary([PrefixBin, ".", FunBin]);
label(BadPrefix, Fun) ->
    erlang:error({bad_prefix, {BadPrefix, Fun}}).

-spec send(Name :: metric_label(),
                  Value :: metric_value(),
                  Type :: metric_type()) -> ok.
%% Send a metric using the metrics module from application config or
%% do nothing.
send(Name, Value, Type) ->
    case envy:get(pushy_common, metrics_module, undefined, atom) of
        undefined -> ok;
        Mod -> Mod:notify(Name, Value, Type)
    end,
    ok.

-spec ctime(binary(), fun(() -> any())) -> any().
%% @doc Update cummulative timer identified by `Label'.
%%
%% If `Fun' is a fun/0, the metric is updated with the time required to execute `Fun()' and
%% its value is returned.
%%
%% You probably want to use the `?TIME_IT' macro in pushy_metrics.hrl instead of calling this
%% function directly.
%%
%% ``?TIME_IT(Mod, Fun, Args)''
%%
%% The `Mod' argument will be mapped to an upstream label as defined in this module.
%% If `Mod' is not recognized, we currently raise an error, but this could be changed
%% to just accept it as part of the label for the metric as-is.
%%
%% The specified MFA will be evaluated and its execution time sent to the folsom
%% worker. This macro returns the value returned by the specified MFA. NOTE: `Args' must be
%% a parenthesized list of args. This is non-standard, but allows us to avoid an apply and
%% still get by with a simple macro.
%%
%% Here's an example call:
%% ``` ?TIME_IT(pushy_command_switch, do_send, (State, OrgName, NodeName, Message))
%% '''
%% And here's the intended expansion:
%% ```
%% pushy_metrics:ctime(<<"send.all">>,
%% fun() -> pushy_command_switch:do_send(State, OrgName, NodeName, Message) end)
%% '''
%%
%% `Mod': atom(); `Fun': atom();
%% `Args': '(a1, a2, ..., aN)'
%%
ctime(Label, Fun) when is_function(Fun) ->
    {Micros, Result} = timer:tc(Fun),
    pushy_metrics:send(<<Label/binary, ".counter">>, {inc, 1}, counter),
    pushy_metrics:send(<<Label/binary, ".histogram">>, Micros, histogram),
    Result.
