xep0363_crypt
=============

XEP-0363 (HTTP File Upload) file encryption/decryption

Build
-----

    $ rebar3 compile

Example
-------

~~~
#!/usr/bin/env escript

main([URI]) ->
  main([URI, "-"]);
main([URI, Filename]) ->
  application:ensure_all_started(ssl),
  application:ensure_all_started(inets),
  {ok, FD} = fd(Filename),
  case xep0363_crypt:download(URI) of
    {ok, PlainText} ->
      io:format(FD, "~s", [PlainText])
    {error, Error} ->
      io:format(standard_error, "~s~n", [Error])
  end.

fd("-") ->
  {ok, standard_io};
fd(Name) ->
  file:open(Name, [write, raw]).
~~~
