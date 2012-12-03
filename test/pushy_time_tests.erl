%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92-*-
%% ex: ts=4 sw=4 et
%% @author James Casey <james@opscode.com>
%% Copyright 2012 Opscode, Inc. All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%


-module(pushy_time_tests).


-include_lib("eunit/include/eunit.hrl").
-include("pushy_client.hrl").

timestamp_test_() ->
    [{"timestamps are generated as ints",
      fun() -> T1 = pushy_time:timestamp(),
               ?assert(is_integer(T1))
      end},
     {"timestamps are monotonically increasing",
      fun() -> T1 = pushy_time:timestamp(),
               T2 = pushy_time:timestamp(),
               ?assert(T2 >= T1)
      end}
    ].

to_secs_test_() ->
    [{"to_secs returns something correct",
      fun() -> ?assertEqual(0, pushy_time:to_secs({0,0,0})),
               ?assertEqual(0, pushy_time:to_secs({0,0,102343})),
               ?assertEqual(10, pushy_time:to_secs({0,10,102343})),
               ?assertEqual(10, pushy_time:to_secs({0,10,0}))
      end},
     {"to_secs of timestamp is sensible",
      fun() -> ?assertEqual(0, pushy_time:to_secs(0)),
               ?assertEqual(10, pushy_time:to_secs(10 * 1000000))
      end}
    ].

diff_test_() ->
    T1 = pushy_time:to_microsecs({0, 10, 102320}),
    T2 = pushy_time:to_microsecs({0, 10, 102321}),
    T3 = pushy_time:to_microsecs({0, 21, 103456}),
    [{"diff_in_secs is ok",
      fun() -> ?assertEqual(0, pushy_time:diff_in_secs(T1, T1)),
               ?assertEqual(0, pushy_time:diff_in_secs(T1, T2)),
               ?assertEqual(11, pushy_time:diff_in_secs(T1, T3))
            end
     }].

