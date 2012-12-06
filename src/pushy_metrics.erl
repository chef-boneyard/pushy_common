%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92-*-
%% ex: ts=4 sw=4 et
%% @author Seth Chisamore <schisamo@opscode.com>
%% @copyright 2012 Opscode, Inc.

%% @doc General metric module
-module(pushy_metrics).

-export([
         app_metric/2,
         label/2,
         ctime/2
        ]).

-define(APP_PREFIX, "app.").
-define(FUN_PREFIX, "function.").

%% @doc generate a name for an application metric
-spec app_metric(Mod :: atom(), Name :: binary()) -> binary().
app_metric(Mod, Name) ->
    ModBin = erlang:atom_to_binary(Mod, utf8),
    iolist_to_binary([?APP_PREFIX, ModBin, ".", Name]).

%% @doc Generate a folsom metric label for module `Mod' and function name `Fun'.
-spec label(Mod :: atom(), Name :: atom()) -> binary().
label(Mod, Fun) ->
    ModBin = erlang:atom_to_binary(Mod, utf8),
    FunBin = erlang:atom_to_binary(Fun, utf8),
    iolist_to_binary([?FUN_PREFIX, ModBin, ".", FunBin]).

-spec ctime(Metric :: binary(),
            Fun :: fun(() -> any())) -> any().
%% @doc Update function timer identified by `Metric'.
%%
%% If `Fun' is a fun/0, the metric is updated with the time required to execute `Fun()' and
%% its value is returned.
%%
%% You probably want to use the `?TIME_IT' macro in pushy_metrics.hrl instead of calling this
%% function directly.
%%
%% ``?TIME_IT(Mod, Fun, Args)''
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
%% pushy_metrics:ctime(<<"function.pushy_command_switch.do_send">>,
%% fun() -> pushy_command_switch:do_send(State, OrgName, NodeName, Message) end)
%% '''
%%
%% `Mod': atom(); `Fun': atom();
%% `Args': '(a1, a2, ..., aN)'
%%
ctime(Metric, Fun) when is_function(Fun) ->
    {Micros, Result} = timer:tc(Fun),
    Millis = Micros/1000,
    folsom_metrics:notify(<<Metric/binary, ".rate">>, 1, meter),
    folsom_metrics:notify(<<Metric/binary, ".duration">>, Millis, histogram),
    Result.

%%
%% Internal functions
%%

