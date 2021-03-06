-module(xep0363_crypt).

%% API exports
-export([
    download/1,
    uri/1,
    fetch/1,
    decrypt/2,
    decrypt_file/2,
    encrypt/1,
    encrypt/2,
    encrypt_file/1, encrypt_file/2,
    iveckey/1
]).

-type key() :: {aesgcm, binary()} | plaintext.

-export_type([key/0]).

%%====================================================================
%% API functions
%%====================================================================

-spec download(string() | binary()) -> {ok, binary()} | {error, term()}.

download(URI) ->
    case fetch(URI) of
        {ok, CipherText, Key} ->
            case decrypt(CipherText, Key) of
                error -> {error, decrypt_failed};
                PlainText -> {ok, PlainText}
            end;
        {error, _} = Error ->
            Error
    end.

-spec uri(string() | binary()) -> {ok, binary(), key()} | {error, atom()}.

uri(URI) when is_list(URI) ->
    uri(list_to_binary(URI));
uri(<<"aesgcm://", URI/binary>>) ->
    case binary:split(URI, <<"#">>) of
        [Path, Key] -> {ok, list_to_binary(["https://", Path]), {aesgcm, Key}};
        _ -> {error, invalid}
    end;
uri(<<"https://", _/binary>> = URI) ->
    {ok, URI, plaintext};
uri(_) ->
    {error, unsupported}.

-spec fetch(string() | binary()) -> {ok, binary(), key()} | {error, term()}.

fetch(URI0) ->
    case uri(URI0) of
        {error, _} = Error ->
            Error;
        {ok, URI, Key} ->
            case httpc:request(binary_to_list(iolist_to_binary(URI))) of
                {ok, {{_, 200, _}, _Headers, Body}} -> {ok, list_to_binary(Body), Key};
                {error, _} = Error -> Error;
                Unknown -> {error, Unknown}
            end
    end.

-spec decrypt_file(file:name_all(), binary() | key()) ->
    {ok, binary()}
    | {error,
        file:posix()
        | badarg
        | terminated
        | system_limit}.

decrypt_file(File, KeyHex) ->
    case file:read_file(File) of
        {ok, CipherText} ->
            case decrypt(CipherText, KeyHex) of
                error -> {error, decrypt_failed};
                PlainText when is_binary(PlainText) -> {ok, PlainText}
            end;
        {error, _} = Error ->
            Error
    end.

-spec iveckey(<<_:768>> | <<_:704>>) -> {<<_:128>> | <<_:96>>, <<_:256>>}.

iveckey(Hex) ->
    Bytes = <<<<(binary_to_integer(N, 16))>> || <<N:2/bytes>> <= Hex>>,
    iveckey_1(Bytes).

% old format
iveckey_1(<<IVec:16/bytes, Key:32/bytes>>) -> {IVec, Key};
% new format
iveckey_1(<<IVec:12/bytes, Key:32/bytes>>) -> {IVec, Key}.

-spec decrypt(iodata(), binary() | key()) -> binary() | error.

decrypt(CipherText, Key) when is_list(CipherText) ->
    decrypt(iolist_to_binary(CipherText), Key);
decrypt(PlainText, plaintext) ->
    PlainText;
decrypt(CipherText, {aesgcm, KeyHex}) ->
    {IVec, KeyBytes} = iveckey(KeyHex),
    CipherLen = byte_size(CipherText) - 16,
    <<CipherData:CipherLen/bytes, CipherTag:16/bytes>> = CipherText,
    crypto:crypto_one_time_aead(
        aes_256_gcm,
        KeyBytes,
        IVec,
        CipherData,
        <<>>,
        CipherTag,
        false
    );
decrypt(CipherText, Key) when is_binary(Key) ->
    decrypt(CipherText, {aesgcm, Key}).

-spec encrypt_file(file:filename_all()) ->
    {ok, {iodata(), binary()}}
    | {error, file:posix() | badarg | terminated | system_limit}.

encrypt_file(File) -> encrypt_file(File, {aesgcm, 16}).

-spec encrypt_file(file:filename_all(), {aesgcm, 12 | 16} | plaintext) ->
    {ok, {iodata(), binary()}}
    | {error,
        file:posix()
        | badarg
        | terminated
        | system_limit}.

encrypt_file(File, {aesgcm, _} = IVLen) ->
    case file:read_file(File) of
        {ok, PlainText} -> {ok, encrypt(PlainText, IVLen)};
        {error, _} = Error -> Error
    end.

-spec encrypt(binary()) -> {iodata(), binary()}.

encrypt(PlainText) -> encrypt(PlainText, {aesgcm, 16}).

-spec encrypt(binary(), {aesgcm, 12 | 16} | plaintext) -> {iodata(), binary() | plaintext}.

encrypt(PlainText, plaintext) ->
    {PlainText, plaintext};
encrypt(PlainText, {aesgcm, IVLen}) ->
    Key = crypto:strong_rand_bytes(32),
    IVec = crypto:strong_rand_bytes(IVLen),
    {CipherText, CipherTag} = crypto:crypto_one_time_aead(
        aes_256_gcm,
        Key,
        IVec,
        PlainText,
        <<>>,
        16,
        true
    ),
    {[CipherText, CipherTag], to_hex(<<IVec/binary, Key/binary>>)}.

%%====================================================================
%% Internal functions
%%====================================================================
to_hex(Bin) -> <<<<(integer_to_binary(X, 16))/binary>> || <<X:4>> <= Bin>>.
