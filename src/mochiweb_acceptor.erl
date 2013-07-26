%% @author Bob Ippolito <bob@mochimedia.com>
%% @copyright 2010 Mochi Media, Inc.

%% @doc MochiWeb acceptor.

-module(mochiweb_acceptor).
-author('bob@mochimedia.com').

-include("internal.hrl").

-export([start_link/4, init/4]).

start_link(Server, Listen, Loop, ProxyProtocol) ->
    proc_lib:spawn_link(?MODULE, init, [Server, Listen, Loop, ProxyProtocol]).

init(Server, Listen, Loop, ProxyProtocol) ->
    T1 = os:timestamp(),
    case catch mochiweb_socket:accept(Listen) of
        {ok, Socket} ->
            gen_server:cast(Server, {accepted, self(), timer:now_diff(os:timestamp(), T1)}),
            Headers = case ProxyProtocol of
                          true ->
                              ok = mochiweb_socket:setopts(Socket, [{active, once}, {packet, line}, list]),
                              {ok, SrcAddr, ProxyPort} = parse_peername_from_proxy_line(Socket),
                              [{"X-Forwarded-For", SrcAddr}, {"Proxy-Proto-Port", ProxyPort}];
                          false ->
                              []
                      end,
            call_loop(Loop, Socket, Headers);
        {error, closed} ->
            exit(normal);
        {error, timeout} ->
            init(Server, Listen, Loop, ProxyProtocol);
        {error, esslaccept} ->
            exit(normal);
        Other ->
            error_logger:error_report(
              [{application, mochiweb},
               "Accept failed error",
               lists:flatten(io_lib:format("~p", [Other]))]),
            exit({error, accept_failed})
    end.

call_loop({M, F}, Socket, _) ->
    M:F(Socket);
call_loop({M, F, [A1]}, Socket, Headers) ->
    M:F(Socket, A1, Headers);
call_loop({M, F, A}, Socket, Headers) ->
    erlang:apply(M, F, [Socket | A] ++ [Headers]);
call_loop(Loop, Socket, _) ->
    Loop(Socket).

parse_peername_from_proxy_line(Sock) ->
	receive
		{TcpOrSsl, Sock, "PROXY " ++ ProxyLine} when TcpOrSsl =:= tcp; TcpOrSsl =:= ssl ->
			case string:tokens(ProxyLine, "\r\n ") of
				[_Proto, SrcAddrStr, _DestAddr, SrcPortStr, DestPort] ->
					{ok, SrcAddrStr, DestPort};
				_ ->
					{error, "got malformed proxy line: ~p", [ProxyLine]}
			end;
		{_, Sock, FirstLine} ->

			{error, ["<h2>PROXY line expected</h2>",
				"Mochiweb configured to expect PROXY line first, as per ",
				"<a href=\"http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt\">the haproxy proxy protocol spec</a>, ",
				"but first line received was:<br/><pre>\r\n",
				FirstLine,
				"\r\n</pre>"]};
		Other ->

			{error, "got from proxy unexpected: ~p", [Other]}
	after 5000 ->

		{error, "timeout on receiving proxy line from upstream proxy"}
	end.

%%
%% Tests
%%
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.
