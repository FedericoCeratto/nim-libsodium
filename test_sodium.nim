#
# Libsodium18 wrapper for Nim
# Unit and functional tests
#
# 2016 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3, see LICENSE file
#

import strutils
import unittest

import libsodium.sodium
import libsodium.sodium_sizes

proc fill[I](arr: var array[I, char], c: char) =
  for i in low(arr)..high(arr): arr[i] = c

proc arrayFromString[I](arr: var array[I, char], str: string) =
  for i in low(arr)..min(high(arr), high(str)):
    arr[i] = str[i]

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
    var
      key, key_bogus: AuthKey

    fill key, 'k'
    fill key_bogus, 'b'

    let mac = crypto_auth("hello", key)
    var mac_bogus: AuthTag

    assert crypto_auth_verify(mac, "hello", key)
    assert crypto_auth_verify(mac, "hallo", key) == false
    assert crypto_auth_verify(mac_bogus, "hello", key) == false
    assert crypto_auth_verify(mac, "hello", key_bogus) == false


  test "hex2bin":
    discard

suite "authenticated encryption":

  test "crypto_secretbox_easy crypto_secretbox_open_easy with nonce":
    var
      key: SecretBoxKey
      nonce: SecretBoxNonce
    randombytes nonce
    fill key, 'k'
    let
      msg = "hello there"
      ciphertext = crypto_secretbox_easy(key, nonce, msg)
      decrypted = crypto_secretbox_open_easy(key, nonce, ciphertext)
    assert msg == decrypted

  test "crypto_secretbox_easy crypto_secretbox_open_easy":
    var key: SecretBoxKey
    fill key, 'k'
    let
      msg = "hello there"
      ciphertext = crypto_secretbox_easy(key, msg)
      decrypted = crypto_secretbox_open_easy(key, ciphertext)
    assert msg == decrypted


# Public-key authenticated encryption
suite "crypto_box":

  test "crypto_box":
    var nonce: BoxNonce
    randombytes nonce
    let
      msg = "hello and goodbye"
      (pk, sk) = crypto_box_keypair()
      ciphertext = crypto_box_easy(msg, nonce, pk, sk)
    assert ciphertext.len == msg.len + crypto_box_MACBYTES

    let orig = crypto_box_open_easy(ciphertext, nonce, pk, sk)
    assert orig == msg
    # FIXME let sig = sign(sk, "hello")
    #assert sig.len == 64


suite "public-key signatures":

  setup:
    var seed: SignSeed
    fill seed, 's'
    let
      (pk, sk) = crypto_sign_seed_keypair(seed)
    assert pk.len == crypto_sign_PUBLICKEYBYTES
    assert sk.len == crypto_sign_SECRETKEYBYTES

  test "real keypair":
    let (real_pk, real_sk) = crypto_sign_keypair()
    assert real_pk.len == crypto_sign_PUBLICKEYBYTES
    assert real_sk.len == crypto_sign_SECRETKEYBYTES

  test "extract seed from secret key":
    assert crypto_sign_ed25519_sk_to_seed(sk) == seed

  test "generate public key from secret key":
    assert crypto_sign_ed25519_sk_to_pk(sk) == pk

  test "sign":
    let sig = crypto_sign_detached(sk, "hello")
    assert sig.len == crypto_sign_BYTES

  test "verify":
    let signature = crypto_sign_detached(sk, "hello")
    checkpoint "verify signature"
    assert crypto_sign_verify_detached(pk, "hello", signature)

    var bogus: SignDetached
    assert crypto_sign_verify_detached(pk, "hello", bogus) == false

  # Sealed boxes

  test "crypto_box_seal":
    let
      msg = "4242424242424242424242"
      sealed = crypto_box_seal(msg, pk)
    assert sealed.len == msg.len + crypto_box_SEALBYTES

  test "crypto_box_seal_open":
    checkpoint "seal"
    let
      msg = "123456789"
      sealed = crypto_box_seal(msg, pk)
    assert sealed.len == msg.len + crypto_box_SEALBYTES
    checkpoint "open"
    # FIXME
    #let opened = crypto_box_seal_open(sealed, pk, sk)
    #assert msg == opened


suite "hashing":

  test "generic hashing":
    let h = crypto_generichash("hello")
    assert h.len == crypto_generichash_BYTES

  test "generic multipart hashing":
    let ha = new_generic_hash(repeat('k', crypto_generichash_KEYBYTES))
    for x in 0..100:
      let ha_old = ha
      ha.update("hello")
      assert ha != ha_old
    skip()
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
      let ha = new_generic_hash(zeroed crypto_generichash_KEYBYTES, 3)
    expect AssertionError:
      let ha = new_generic_hash(zeroed crypto_generichash_KEYBYTES, 9999)

  test "shorthash":
    let
      k = generate_key_for_short_hash()
      k2 = generate_key_for_short_hash()
      h = crypto_shorthash("hello", k)
      h2 = crypto_shorthash("hello", k)
      h_using_k2 = crypto_shorthash("hello", k2)
    assert h == h2
    assert h != h_using_k2
    assert k.len == crypto_shorthash_KEYBYTES
    assert h.len == crypto_shorthash_BYTES

test "Diffie-Hellman function":

  test "scalarmult base":
    var secret_key: BoxSecretKey
    fill secret_key, 'k'
    let
      public_key = crypto_scalarmult_base(secret_key)
    assert bin2hex(public_key) == "8462fb3f0798f9fe2c39f3823bb41cd3effe70bb5c81735be46a143135c58454"

  test "scalarmult":
    var secret_key1, secret_key2: BoxSecretKey
    fill secret_key1, 'k'
    fill secret_key2, 'z'
    let
      public_key1 = crypto_scalarmult_base(secret_key1)
      public_key2 = crypto_scalarmult_base(secret_key2)
      shared_secret12 = crypto_scalarmult(secret_key1, public_key2)
      shared_secret21 = crypto_scalarmult(secret_key2, public_key1)
    assert bin2hex(shared_secret12) == "806b0dffd3436ce81b12c4283db697bcfaab98571910ad33d3f385ec5409c009"
    assert shared_secret12 == shared_secret21

test "poly1305 onetimeauth":
  var
    key, bogus_key: OneTimeAuthKey
    bogus_tok: OneTimeAuthTag
  fill key, 'k'
  fill bogus_key, 'x'
  fill bogus_tok, 'z'
  let
    msg = repeat('m', 33)
    tok = crypto_onetimeauth(msg, key)
    ok = crypto_onetimeauth_verify(tok, msg, key)
  assert ok
  assert tok.len == crypto_onetimeauth_BYTES

  let bogus_msg = repeat('m', 32)
  assert crypto_onetimeauth_verify(tok, bogus_msg, key) == false
  assert crypto_onetimeauth_verify(bogus_tok, msg, key) == false
  assert crypto_onetimeauth_verify(tok, msg, bogus_key) == false

