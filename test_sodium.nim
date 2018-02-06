# 2017 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3, see LICENSE file
#
## Libsodium wrapper for Nim
##
## Unit and functional tests

import strutils
import unittest

import libsodium.sodium
import libsodium.sodium_sizes

suite "basics":

  test "zeroed":
    let s = zeroed 20
    assert s == repeat('\0', 20)

  test "memcmp":
    assert memcmp("hello", "hello")
    assert memcmp("hello", "hello2") == false
    assert memcmp("hello2", "hello") == false
    assert memcmp("hello", "hallo") == false

  test "is zero":
    assert is_zero("")
    assert is_zero("\0\0\0")
    assert is_zero("\0\0\1") == false
    assert zeroed(20).is_zero()

  test "bin2hex":
    assert bin2hex("") == ""
    assert bin2hex("\0\255") == "00ff"
    assert bin2hex("\255\0") == "ff00"
    assert bin2hex("\0\1\2\3\4\5\6\7\8\9") == "00010203040506070809"

  test "hex2bin":
    assert hex2bin("") == ""
    assert hex2bin("00ff") == "\0\255"
    assert hex2bin("ff00") == "\255\0"
    assert hex2bin("ff:aa:bb:cc", ignore=":") == "\xFF\xAA\xBB\xCC\0"
    # FIXME
    #assert hex2bin("ff:aa:bb:cc", ignore=":").len == 4
    #assert hex2bin("00010203040506070809") == "\0\x01\x02\x03\x04\x05\x06\x07\x08\x09"

  test "random":
    var r = randombytes(8)
    assert r.len == 8

  test "auth":
    let
      key = repeat('k', crypto_auth_KEYBYTES())
      mac = crypto_auth("hello", key)
    assert mac.len == crypto_auth_BYTES()
    assert crypto_auth_verify(mac, "hello", key)
    assert crypto_auth_verify(mac, "hallo", key) == false
    let mac_bogus = zeroed crypto_auth_BYTES()
    assert crypto_auth_verify(mac_bogus, "hello", key) == false
    let key_bogus = repeat('b', crypto_auth_KEYBYTES())
    assert crypto_auth_verify(mac, "hello", key_bogus) == false


  test "hex2bin":
    discard

suite "authenticated encryption":

  test "crypto_secretbox_easy crypto_secretbox_open_easy":
    let
      key = repeat('k', crypto_secretbox_KEYBYTES())
      msg = "hello there"
      ciphertext = crypto_secretbox_easy(key, msg)
      decrypted = crypto_secretbox_open_easy(key, ciphertext)
    assert msg == decrypted


# Public-key authenticated encryption
suite "crypto_box":

  test "crypto_box":
    let
      msg = "hello and goodbye"
      (pk, sk) = crypto_box_keypair()
      nonce = randombytes(crypto_box_NONCEBYTES())
      ciphertext = crypto_box_easy(msg, nonce, pk, sk)
    assert ciphertext.len == msg.len + crypto_box_MACBYTES()

    let orig = crypto_box_open_easy(ciphertext, nonce, pk, sk)
    assert orig == msg
    # FIXME let sig = sign(sk, "hello")
    #assert sig.len == 64


suite "public-key signatures":

  setup:
    let
      seed = repeat('s', crypto_sign_SEEDBYTES())
      (pk, sk) = crypto_sign_seed_keypair(seed)
    assert pk.len == crypto_sign_PUBLICKEYBYTES()
    assert sk.len == crypto_sign_SECRETKEYBYTES()

  test "real keypair":
    let (real_pk, real_sk) = crypto_sign_keypair()
    assert real_pk.len == crypto_sign_PUBLICKEYBYTES()
    assert real_sk.len == crypto_sign_SECRETKEYBYTES()

  test "extract seed from secret key":
    assert crypto_sign_ed25519_sk_to_seed(sk) == seed

  test "generate public key from secret key":
    assert crypto_sign_ed25519_sk_to_pk(sk) == pk

  test "sign":
    let sig = crypto_sign_detached(sk, "hello")
    assert sig.len == crypto_sign_BYTES()

  test "verify":
    let signature = crypto_sign_detached(sk, "hello")
    checkpoint "verify signature"
    crypto_sign_verify_detached(pk, "hello", signature)
    checkpoint "verify signature, expect SodiumError"
    expect SodiumError:
      crypto_sign_verify_detached(pk, "hello", signature[0..^2] & "X")

  # Sealed boxes

  test "crypto_box_seal":
    let
      msg = "4242424242424242424242"
      sealed = crypto_box_seal(msg, pk)
    assert sealed.len == msg.len + crypto_box_SEALBYTES()

  test "crypto_box_seal_open":
    checkpoint "seal"
    let
      msg = "123456789"
      sealed = crypto_box_seal(msg, pk)
    assert sealed.len == msg.len + crypto_box_SEALBYTES()
    checkpoint "open"
    # FIXME
    #let opened = crypto_box_seal_open(sealed, pk, sk)
    #assert msg == opened


suite "hashing":

  test "generic hashing":
    let h = crypto_generichash("hello")
    assert h.len == crypto_generichash_BYTES()

  test "generic multipart hashing":
    let ha = new_generic_hash(repeat('k', crypto_generichash_KEYBYTES()))
    skip()
    #for x in 0..100:
    #  let ha_old = ha
    #  ha.update("hello")
    #  assert ha != ha_old
    #let h = ha.finalize()
    #assert bin2hex(h) == "3d76eda4eaf33f6bf73ab54a37e86e1a87a" &
    #  "fbe5fb803e727cbcb33c082f32035"

  test "generic multipart hashing key = nil":
    let ha = new_generic_hash(nil, 33)
    ha.update("hello")
    skip()
    #let h = ha.finalize()
    #assert bin2hex(h) == "1fc1d1cb09e15737e79c9a3a687bc751e07" &
    #  "d151c2da09ecb65ea8b8b38c89b03af"

  test "generic multipart hashing bad sizes":
    expect AssertionError:
      let ha = new_generic_hash("short key")
    expect AssertionError:
      let ha = new_generic_hash(zeroed 999)
    expect AssertionError:
      let ha = new_generic_hash(zeroed crypto_generichash_KEYBYTES(), 3)
    expect AssertionError:
      let ha = new_generic_hash(zeroed crypto_generichash_KEYBYTES(), 9999)

  test "shorthash":
    let
      k = generate_key_for_short_hash()
      k2 = generate_key_for_short_hash()
      h = crypto_shorthash("hello", k)
      h2 = crypto_shorthash("hello", k)
      h_using_k2 = crypto_shorthash("hello", k2)
    assert h == h2
    assert h != h_using_k2
    assert k.len == crypto_shorthash_KEYBYTES()
    assert h.len == crypto_shorthash_BYTES()

test "Diffie-Hellman function":

  test "scalarmult base":
    let
      secret_key = repeat('k', crypto_scalarmult_SCALARBYTES())
      public_key = crypto_scalarmult_base(secret_key)
    assert public_key == hex2bin "8462fb3f0798f9fe2c39f3823bb41cd3effe70bb5c81735be46a143135c58454"

  test "scalarmult":
    let
      secret_key1 = repeat('k', crypto_scalarmult_SCALARBYTES())
      public_key1 = crypto_scalarmult_base(secret_key1)
      secret_key2 = repeat('z', crypto_scalarmult_SCALARBYTES())
      public_key2 = crypto_scalarmult_base(secret_key2)
      shared_secret12 = crypto_scalarmult(secret_key1, public_key2)
      shared_secret21 = crypto_scalarmult(secret_key2, public_key1)
    assert shared_secret12.bin2hex() == "806b0dffd3436ce81b12c4283db697bcfaab98571910ad33d3f385ec5409c009"
    assert shared_secret12 == shared_secret21

test "poly1305 onetimeauth":
  let
    msg = repeat('m', 33)
    key = repeat('k', crypto_onetimeauth_KEYBYTES())
    tok = crypto_onetimeauth(msg, key)
    ok = crypto_onetimeauth_verify(tok, msg, key)
  assert ok
  assert tok.len == crypto_onetimeauth_BYTES()

  let bogus_msg = repeat('m', 32)
  assert crypto_onetimeauth_verify(tok, bogus_msg, key) == false
  let bogus_tok = repeat('z', crypto_onetimeauth_BYTES())
  assert crypto_onetimeauth_verify(bogus_tok, msg, key) == false
  let bogus_key = repeat('x', crypto_onetimeauth_KEYBYTES())
  assert crypto_onetimeauth_verify(tok, msg, bogus_key) == false


suite "HMAC":

  const msg = repeat("n", 1000)

  test "HMAC short key":
    expect AssertionError:
      let
        key = repeat("k", crypto_auth_keybytes() - 1)
        h = crypto_auth(msg, key)

  test "HMAC":
    let
      key = repeat("k", crypto_auth_keybytes())
      h = crypto_auth(msg, key)
    check crypto_auth_verify(h, msg, key) == true
    check h.bin2hex() == "24deaa07e4739fc6f4870cd2021b3a220958df7ca43ad576a387f0eebb20b79e"

  test "HMAC invalid signature":
    let
      key = repeat("k", crypto_auth_keybytes())
      h = crypto_auth(msg, key)
    check crypto_auth_verify(h, msg & "X", key) == false


  # SHA256

  test "HMAC SHA256 short key":
    expect AssertionError:
      let
        key = repeat("k", crypto_auth_hmacsha256_keybytes() - 1)
        h = crypto_auth_hmacsha256(msg, key)

  test "HMAC SHA256":
    let
      key = repeat("k", crypto_auth_hmacsha256_keybytes())
      h = crypto_auth_hmacsha256(msg, key)
    check crypto_auth_hmacsha256_verify(h, msg, key) == true
    check h.bin2hex() == "883225c5a7cb0af67ea5be42278287dbff875da22a39bd209eb5623c4123159c"

  test "HMAC SHA256 invalid signature":
    let
      key = repeat("k", crypto_auth_hmacsha256_keybytes())
      h = crypto_auth_hmacsha256(msg, key)
    check crypto_auth_hmacsha256_verify(h, msg & "X", key) == false


suite "stream ciphers":

  test "Salsa20 keygen":
    let key = crypto_stream_salsa20_keygen()
    check crypto_auth_KEYBYTES() == 32
    check key.len == crypto_auth_KEYBYTES()

  test "Salsa20 stream":
    expect AssertionError:
      let nonce = repeat("n", crypto_stream_salsa20_NONCEBYTES())
      discard crypto_stream_salsa20(nonce, "", 1024)

    expect AssertionError:
      let key = crypto_stream_salsa20_keygen()
      discard crypto_stream_salsa20("", key, 1024)

    let
      key = repeat("k", crypto_stream_salsa20_KEYBYTES())
      nonce = repeat("n", crypto_stream_salsa20_NONCEBYTES())
      c = crypto_stream_salsa20(nonce, key, 64)
    check c.bin2hex() == "83243f860e8d26b2396dc747e122ce2de52c75b7e0ca57f81d332bbafb8a1fae3d53acf28e021e2afb00a723f9540d9760dd3dcfd54ffbb69e59e76a79f72017"

  test "Salsa20 stream xor":
    let
      key = repeat("k", crypto_stream_salsa20_KEYBYTES())
      nonce = repeat("n", crypto_stream_salsa20_NONCEBYTES())
      msg = "hello there"
      c = crypto_stream_salsa20_xor(nonce, key, msg)
    check c.bin2hex() == "eb4153ea61ad52da5c1fa2"

    let decrypted = crypto_stream_salsa20_xor(nonce, key, c)
    check decrypted == "hello there"

  test "Salsa20 stream xor ic":
    let
      key = repeat("k", crypto_stream_salsa20_KEYBYTES())
      nonce = repeat("n", crypto_stream_salsa20_NONCEBYTES())
      msg = "hello there"
      c = crypto_stream_salsa20_xor_ic(nonce, key, msg, 10)
    check c.bin2hex() == "6496a6e3ee2d220ba22928"

    let decrypted = crypto_stream_salsa20_xor_ic(nonce, key, c, 10)
    check decrypted == "hello there"

    let decrypted_wrong_ic = crypto_stream_salsa20_xor_ic(nonce, key, c, 11)
    check decrypted_wrong_ic != "hello there"

  test "Salsa20 stream xor ic 0":
    let
      key = repeat("k", crypto_stream_salsa20_KEYBYTES())
      nonce = repeat("n", crypto_stream_salsa20_NONCEBYTES())
      msg = "hello there"
      c = crypto_stream_salsa20_xor(nonce, key, msg)

    let decrypted = crypto_stream_salsa20_xor_ic(nonce, key, c, 0)
    check decrypted == "hello there"
