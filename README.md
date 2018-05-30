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
  {ok, Key, CipherText} = xep0363_crypt:fetch(URI),
  case xep0363_crypt:decrypt(CipherText, Key) of
    error ->
      io:format(standard_error, "~s~n", ["decrypt error"]);
    PlainText ->
      io:format(fd(Filename), "~s", [PlainText])
  end.

fd("-") ->
  standard_io;
fd(Name) ->
  {ok, FD} = file:open(Name, [write, raw]),
  FD.
~~~
