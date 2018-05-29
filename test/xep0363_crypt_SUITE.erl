-module(xep0363_crypt_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/file.hrl").

-export([
         all/0
        ]).

-export([
         uri/1,
         decrypt_file/1,
         encrypt/1
        ]).

-define(KEY, <<"1bf982a9ec7603a7d84fbc90a495935c4dff5c4ddec37e133c38234f92fdbd1b2e6c0f187ef6a055206c8dcf79414d37">>).

all() ->
  [uri, decrypt_file, encrypt].

uri(_Config) ->
  {ok, <<"https://example.com/foo">>, {aesgcm, <<"abc123">>}} = xep0363_crypt:uri(
    "aesgcm://example.com/foo#abc123"
  ),
  {ok, <<"https://example.com/foo">>, plaintext} = xep0363_crypt:uri(
    "https://example.com/foo"
  ),
  {error, invalid} = xep0363_crypt:uri(
    "aesgcm://example.com/foo"
  ),
  {error, unsupported} = xep0363_crypt:uri(
    "http://example.com/foo"
  ).

decrypt_file(_Config) ->
  {ok,<<"abcdefghijklmnopqrstuvwxyz\n0123456789\n">>} = xep0363_crypt:decrypt_file("../../../../test/test.txt", ?KEY).

encrypt(_Config) ->
  TestMessage = <<"this\nis a test message\n">>,
  {CipherText, KeyHex} = xep0363_crypt:encrypt(TestMessage),
  TestMessage = xep0363_crypt:decrypt(CipherText, KeyHex).
