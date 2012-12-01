%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% @copyright 2012 Opscode Inc.
%%
%% @doc Some helpers for computing timestamps

-module(pushy_time).

-export([timestamp/0,
         to_microsecs/1,
         to_secs/1,
         diff_in_secs/2
        ]).

-define(MEGA, 1000000). %% because I can't count zeros reliably

%% @doc Return the current time in microsecs
timestamp() ->
    {M, S, U} = os:timestamp(),
    to_microsecs({M, S, U}).

%% @convert a time returned by os:timestamp()
%% to a timestamp in microsecs
to_microsecs({M, S, U}) ->
    ((M*?MEGA) + S) * ?MEGA + U.

to_secs({M, S, _U}) ->
    ((M*?MEGA) + S);
to_secs(Timestamp) when is_integer(Timestamp) ->
    Timestamp div ?MEGA.

%% @doc The different in two integer times (as returned by timestamp/0)
%% returned in seconds
-spec diff_in_secs(non_neg_integer(), non_neg_integer()) -> float().
diff_in_secs(T1, T2) ->
    to_secs(T2) - to_secs(T1).

