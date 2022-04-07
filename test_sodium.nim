# 2017 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3, see LICENSE file
#
## Libsodium wrapper for Nim
##
## Unit and functional tests

import strutils
import unittest

import libsodium/sodium
import libsodium/sodium_sizes

suite "basics":

  test "zeroed":
    let s = zeroed 20
    check s == repeat('\0', 20)

  test "memcmp":
    check memcmp("hello", "hello")
    check memcmp("hello", "hello2") == false
    check memcmp("hello2", "hello") == false
    check memcmp("hello", "hallo") == false

  test "is zero":
    check is_zero("")
    check is_zero("\0\0\0")
    check is_zero("\0\0\1") == false
    check zeroed(20).is_zero()

  test "bin2hex":
    check bin2hex("") == ""
    check bin2hex("\0\255") == "00ff"
    check bin2hex("\255\0") == "ff00"
    check bin2hex("\0\1\2\3\4\5\6\7\8\9") == "00010203040506070809"

  test "hex2bin":
    check hex2bin("") == ""
    check hex2bin("00ff") == "\0\255"
    check hex2bin("ff00") == "\255\0"
    check hex2bin("ff:aa:bb:cc", ignore = ":") == "\xFF\xAA\xBB\xCC\0"
    # FIXME
    #check hex2bin("ff:aa:bb:cc", ignore=":").len == 4
    #check hex2bin("00010203040506070809") == "\0\x01\x02\x03\x04\x05\x06\x07\x08\x09"

  test "random":
    var r = randombytes(8)
    check r.len == 8
    check randombytes_uniform(42) < 42'u32

  test "auth":
    let
      key = repeat('k', crypto_auth_KEYBYTES())
      mac = crypto_auth("hello", key)
    check mac.len == crypto_auth_BYTES()
    check crypto_auth_verify(mac, "hello", key)
    check crypto_auth_verify(mac, "hallo", key) == false
    let mac_bogus = zeroed crypto_auth_BYTES()
    check crypto_auth_verify(mac_bogus, "hello", key) == false
    let key_bogus = repeat('b', crypto_auth_KEYBYTES())
    check crypto_auth_verify(mac, "hello", key_bogus) == false


  test "hex2bin":
    discard

suite "authenticated encryption":

  test "crypto_secretbox_keygen":
    let k = crypto_secretbox_keygen()
    check k.len == crypto_secretbox_KEYBYTES()

  test "crypto_secretbox_easy crypto_secretbox_open_easy":
    let
      key = repeat('k', crypto_secretbox_KEYBYTES())
      msg = "hello there"
      ciphertext = crypto_secretbox_easy(key, msg)
      decrypted = crypto_secretbox_open_easy(key, ciphertext)
    check msg == decrypted


# Public-key authenticated encryption
suite "crypto_box":

  test "crypto_box":
    let
      msg = "hello and goodbye"
      (pk, sk) = crypto_box_keypair()
      nonce = randombytes(crypto_box_NONCEBYTES())
      ciphertext = crypto_box_easy(msg, nonce, pk, sk)
    check ciphertext.len == msg.len + crypto_box_MACBYTES()

    let orig = crypto_box_open_easy(ciphertext, nonce, pk, sk)
    check orig == msg
    # FIXME let sig = sign(sk, "hello")
    #check sig.len == 64


suite "public-key signatures":

  setup:
    let
      seed = repeat('s', crypto_sign_SEEDBYTES())
      (pk, sk) = crypto_sign_seed_keypair(seed)
    check pk.len == crypto_sign_PUBLICKEYBYTES()
    check sk.len == crypto_sign_SECRETKEYBYTES()

  test "real keypair":
    let (real_pk, real_sk) = crypto_sign_keypair()
    check real_pk.len == crypto_sign_PUBLICKEYBYTES()
    check real_sk.len == crypto_sign_SECRETKEYBYTES()

  test "extract seed from secret key":
    check crypto_sign_ed25519_sk_to_seed(sk) == seed

  test "generate public key from secret key":
    check crypto_sign_ed25519_sk_to_pk(sk) == pk

  test "sign detached":
    let sig = crypto_sign_detached(sk, "hello")
    check sig.len == crypto_sign_BYTES()

  test "verify detached":
    let signature = crypto_sign_detached(sk, "hello")
    checkpoint "verify signature"
    crypto_sign_verify_detached(pk, "hello", signature)
    checkpoint "verify signature, expect SodiumError"
    expect SodiumError:
      crypto_sign_verify_detached(pk, "hello", signature[0..^2] & "X")

  test "sign and verify combined":
    let sig = crypto_sign(sk, "some message to sign")
    let original = crypto_sign_open(pk, sig)
    check original == "some message to sign"

    checkpoint "expect SodiumError"
    let (other_pk, other_sk) = crypto_sign_keypair()
    expect SodiumError:
      discard crypto_sign_open(other_pk, sig)

  # Sealed boxes

  test "crypto_box_seal":
    let
      msg = "4242424242424242424242"
      sealed = crypto_box_seal(msg, pk)
    check sealed.len == msg.len + crypto_box_SEALBYTES()

  test "crypto_box_seal_open":
    checkpoint "seal"
    let
      msg = "123456789"
      sealed = crypto_box_seal(msg, pk)
    check sealed.len == msg.len + crypto_box_SEALBYTES()
    checkpoint "open"
    # FIXME
    #let opened = crypto_box_seal_open(sealed, pk, sk)
    #check msg == opened


suite "hashing":

  test "generic hashing":
    let h = crypto_generichash("hello")
    check h.len == crypto_generichash_BYTES()

  test "generic multipart hashing":
    let ha = new_generic_hash(repeat('k', crypto_generichash_KEYBYTES()))
    skip()
    #for x in 0..100:
    #  let ha_old = ha
    #  ha.update("hello")
    #  check ha != ha_old
    #let h = ha.finalize()
    #check bin2hex(h) == "3d76eda4eaf33f6bf73ab54a37e86e1a87a" &
    #  "fbe5fb803e727cbcb33c082f32035"

  test "generic multipart hashing key is empty":
    let ha = new_generic_hash("", 33)
    ha.update("hello")
    skip()
    let h = ha.finalize()
    check bin2hex(h) == "1fc1d1cb09e15737e79c9a3a687bc751e07" &
      "d151c2da09ecb65ea8b8b38c89b03af"

  test "generic multipart hashing bad sizes":
    expect AssertionDefect:
      let ha = new_generic_hash("short key")
    expect AssertionDefect:
      let ha = new_generic_hash(zeroed 999)
    expect AssertionDefect:
      let ha = new_generic_hash(zeroed crypto_generichash_KEYBYTES(), 3)
    expect AssertionDefect:
      let ha = new_generic_hash(zeroed crypto_generichash_KEYBYTES(), 9999)

  test "shorthash":
    let
      k = generate_key_for_short_hash()
      k2 = generate_key_for_short_hash()
      h = crypto_shorthash("hello", k)
      h2 = crypto_shorthash("hello", k)
      h_using_k2 = crypto_shorthash("hello", k2)
    check k.len == crypto_shorthash_KEYBYTES()
    check k2.len == crypto_shorthash_KEYBYTES()
    check k != k2
    check h.len == crypto_shorthash_BYTES()
    check h == h2
    check h != h_using_k2

suite "password hashing":
  const password = "Correct Horse Battery Staple"
  let salt = cast[seq[byte]](randombytes crypto_pwhash_saltbytes().int)

  for i in PasswordHashingAlgorithm:
    test "password hashing (" & $i & ")":
      let h = crypto_pwhash(password, salt, 32, i)
      check h.len == 32

  for i in PasswordHashingAlgorithm:
    test "password hashing & verification (" & $i & ")":
      let h = crypto_pwhash_str(password, i)
      check crypto_pwhash_str_verify(h, password) == true

  test "password rehash required":
    let h = crypto_pwhash_str(password, opslimit = crypto_pwhash_opslimit_min(),
                              memlimit = crypto_pwhash_memlimit_min())
    check crypto_pwhash_str_needs_rehash(h) > 0

  test "password no needs rehash":
    let h = crypto_pwhash_str(password)
    check crypto_pwhash_str_needs_rehash(h) == 0

test "Diffie-Hellman function":

  test "scalarmult base":
    let
      secret_key = repeat('k', crypto_scalarmult_SCALARBYTES())
      public_key = crypto_scalarmult_base(secret_key)
    check public_key == hex2bin "8462fb3f0798f9fe2c39f3823bb41cd3effe70bb5c81735be46a143135c58454"

  test "scalarmult":
    let
      secret_key1 = repeat('k', crypto_scalarmult_SCALARBYTES())
      public_key1 = crypto_scalarmult_base(secret_key1)
      secret_key2 = repeat('z', crypto_scalarmult_SCALARBYTES())
      public_key2 = crypto_scalarmult_base(secret_key2)
      shared_secret12 = crypto_scalarmult(secret_key1, public_key2)
      shared_secret21 = crypto_scalarmult(secret_key2, public_key1)
    check shared_secret12.bin2hex() == "806b0dffd3436ce81b12c4283db697bcfaab98571910ad33d3f385ec5409c009"
    check shared_secret12 == shared_secret21

test "poly1305 onetimeauth":
  let
    msg = repeat('m', 33)
    key = repeat('k', crypto_onetimeauth_KEYBYTES())
    tok = crypto_onetimeauth(msg, key)
    ok = crypto_onetimeauth_verify(tok, msg, key)
  check ok
  check tok.len == crypto_onetimeauth_BYTES()

  let bogus_msg = repeat('m', 32)
  check crypto_onetimeauth_verify(tok, bogus_msg, key) == false
  let bogus_tok = repeat('z', crypto_onetimeauth_BYTES())
  check crypto_onetimeauth_verify(bogus_tok, msg, key) == false
  let bogus_key = repeat('x', crypto_onetimeauth_KEYBYTES())
  check crypto_onetimeauth_verify(tok, msg, bogus_key) == false


suite "HMAC":

  const msg = repeat("n", 1000)

  test "HMAC short key":
    expect AssertionDefect:
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
    expect AssertionDefect:
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

  test "HMAC SHA256 multipart":
    let key = repeat("k", crypto_auth_hmacsha256_keybytes())
    var hm = new_crypto_auth_hmacsha256(key)
    hm.update(msg)
    let h = hm.finalize()
    # same as non-multipart test
    check h.bin2hex() == "883225c5a7cb0af67ea5be42278287dbff875da22a39bd209eb5623c4123159c"

  test "HMAC SHA256 multipart":
    let key = repeat("k", crypto_auth_hmacsha256_keybytes())
    var hm = new_crypto_auth_hmacsha256(key)
    hm.update("hi")
    hm.update("hello")
    let h = hm.finalize()
    check h.bin2hex() == "65c6c6abb234c900c0350935756ae38dbe08dc209c03f18886a18794059ca353"

  # SHA512

  test "HMAC SHA512 short key":
    expect AssertionDefect:
      let
        key = repeat("k", crypto_auth_hmacsha512_keybytes() - 1)
        h = crypto_auth_hmacsha512(msg, key)

  test "HMAC SHA512":
    let
      key = repeat("k", crypto_auth_hmacsha512_keybytes())
      h = crypto_auth_hmacsha512(msg, key)
    check crypto_auth_hmacsha512_verify(h, msg, key) == true
    check h.bin2hex() == "24deaa07e4739fc6f4870cd2021b3a220958df7ca43ad576a387f0eebb20b79e1d1e510c3fb81e20a83063ae9cfd1d9e64b8c855ff4846caa35ddb83f0096588"

  test "HMAC SHA512 invalid signature":
    let
      key = repeat("k", crypto_auth_hmacsha512_keybytes())
      h = crypto_auth_hmacsha512(msg, key)
    check crypto_auth_hmacsha512_verify(h, msg & "X", key) == false

  test "HMAC SHA512 multipart":
    let key = repeat("k", crypto_auth_hmacsha512_keybytes())
    var hm = new_crypto_auth_hmacsha512(key)
    hm.update512(msg)
    let h = hm.finalize512()
    # same as non-multipart test
    check h.bin2hex() == "24deaa07e4739fc6f4870cd2021b3a220958df7ca43ad576a387f0eebb20b79e1d1e510c3fb81e20a83063ae9cfd1d9e64b8c855ff4846caa35ddb83f0096588"

  test "HMAC SHA512 multipart":
    let key = repeat("k", crypto_auth_hmacsha512_keybytes())
    var hm = new_crypto_auth_hmacsha512(key)
    hm.update512("hi")
    hm.update512("hello")
    let h = hm.finalize512()
    check h.bin2hex() == "c635ca75467429607483b8973b8e6952d186e89f56bc6f610bec766a1150997a0a4ab1664eefa97ecbc60e31a4422b086aae160ff75c07198cfc2c740cb3958c"


suite "stream ciphers":

  test "Salsa20 sizes":
    check crypto_stream_salsa20_NONCEBYTES() * 8 == 64
    check crypto_stream_salsa20_KEYBYTES() * 8 == 256

  test "Salsa20 keygen":
    let key = crypto_stream_salsa20_keygen()
    check crypto_auth_KEYBYTES() == 32
    check key.len == crypto_auth_KEYBYTES()

  test "Salsa20 stream":
    expect AssertionDefect:
      let nonce = repeat("n", crypto_stream_salsa20_NONCEBYTES())
      discard crypto_stream_salsa20(nonce, "", 1024)

    expect AssertionDefect:
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

  # XSalsa20

  test "XSalsa20 sizes":
    check crypto_stream_xsalsa20_NONCEBYTES() * 8 == 192
    check crypto_stream_xsalsa20_KEYBYTES() * 8 == 256

  test "XSalsa20 keygen":
    let key = crypto_stream_keygen()
    check crypto_auth_KEYBYTES() == 32
    check key.len == crypto_auth_KEYBYTES()

  test "XSalsa20 stream":
    expect AssertionDefect:
      let nonce = repeat("n", crypto_stream_xsalsa20_NONCEBYTES())
      discard crypto_stream(nonce, "", 1024)

    expect AssertionDefect:
      let key = crypto_stream_keygen()
      discard crypto_stream("", key, 1024)

    let
      key = repeat("k", crypto_stream_xsalsa20_KEYBYTES())
      nonce = repeat("n", crypto_stream_xsalsa20_NONCEBYTES())
      c = crypto_stream(nonce, key, 64)
    check c.bin2hex() == "91172bd584998fa76d97a543eccf9eafdde4107708b45dda53ad660ebfc44656c8c850d59229d2a15e54fb6a1119be624e1880c0916eb6e08b2557e1d03db9da"

  test "XSalsa20 stream xor":
    const
      key = "this is 32-byte key for xsalsa20"
      nonce = "24-byte nonce for xsalsa"
      msg = "Hello world!"
    let
      c = crypto_stream_xor(nonce, key, msg)
    check c.bin2hex() == "002d4513843fc240c401e541"

    let decrypted = crypto_stream_xor(nonce, key, c)
    check decrypted == msg

  test "XSalsa20 stream xor":
    let
      key = repeat("k", crypto_stream_xsalsa20_KEYBYTES())
      nonce = repeat("n", crypto_stream_xsalsa20_NONCEBYTES())
      msg = "hello there"
      c = crypto_stream_xor(nonce, key, msg)
    check c.bin2hex() == "f97247b9ebb9fbcf08e5c0"

    let decrypted = crypto_stream_xor(nonce, key, c)
    check decrypted == "hello there"

suite "key exchange":

  test "kx sizes":
    check crypto_kx_PUBLICKEYBYTES() * 8 == 256
    check crypto_kx_SECRETKEYBYTES() * 8 == 256
    check crypto_kx_SESSIONKEYBYTES() * 8 == 256

  test "crypto_kx_keypair":
    let (pk, sk) = crypto_kx_keypair()
    check pk.len == crypto_kx_PUBLICKEYBYTES()
    check sk.len == crypto_kx_SECRETKEYBYTES()

  test "crypto_kx_client_session_keys":
    let
      (cpub, csec) = crypto_kx_keypair() # client
      (spub, ssec) = crypto_kx_keypair() # server
      (rx, tx) = crypto_kx_client_session_keys(cpub, csec, spub)
    check rx.len == crypto_kx_SESSIONKEYBYTES()
    check tx.len == crypto_kx_SESSIONKEYBYTES()

  test "crypto_kx_server_session_keys":
    let
      (cpub, csec) = crypto_kx_keypair() # client
      (spub, ssec) = crypto_kx_keypair() # server
      (rx, tx) = crypto_kx_server_session_keys(spub, ssec, cpub)
    check rx.len == crypto_kx_SESSIONKEYBYTES()
    check tx.len == crypto_kx_SESSIONKEYBYTES()

  test "session key with crypto_secretbox":
    let
      (cpub, csec) = crypto_kx_keypair() # client
      (spub, ssec) = crypto_kx_keypair() # server
      (crx, ctx) = crypto_kx_client_session_keys(cpub, csec, spub)
      (srx, stx) = crypto_kx_server_session_keys(spub, ssec, cpub)

    # client to server
    let
      cipher1 = crypto_secretbox_easy(ctx, "hello from client")
      plain1 = crypto_secretbox_open_easy(srx, cipher1)
    check plain1 == "hello from client"

    # server to client
    let
      cipher2 = crypto_secretbox_easy(stx, "hello from server")
      plain2 = crypto_secretbox_open_easy(crx, cipher2)
    check plain2 == "hello from server"


suite "secretstream_xchacha20poly1305":

  test "sizes":
    check crypto_secretstream_xchacha20poly1305_KEYBYTES() * 8 == 256
    check crypto_secretstream_xchacha20poly1305_HEADERBYTES() > 0

  test "keygen":
    let key = crypto_secretstream_xchacha20poly1305_keygen()
    check key.len == crypto_secretstream_xchacha20poly1305_KEYBYTES()

  test "encrypt and decrypt":
    let
      key = crypto_secretstream_xchacha20poly1305_keygen()
      (push_state, header) = crypto_secretstream_xchacha20poly1305_init_push(key)
      pull_state = crypto_secretstream_xchacha20poly1305_init_pull(header, key)
      plain1 = "Hello, there"
      plain2 = "this is message 2"
      cipher1 = push_state.push(plain1, "",
          crypto_secretstream_xchacha20poly1305_tag_message())
      cipher2 = push_state.push(plain2, "",
          crypto_secretstream_xchacha20poly1305_tag_final())
      (msg1, tag1) = pull_state.pull(cipher1, "")
      (msg2, tag2) = pull_state.pull(cipher2, "")

    check cipher1.len == plain1.len + crypto_secretstream_xchacha20poly1305_ABYTES()
    check cipher2.len == plain2.len + crypto_secretstream_xchacha20poly1305_ABYTES()
    check msg1 == plain1
    check tag1 == crypto_secretstream_xchacha20poly1305_tag_message()
    check msg2 == plain2
    check tag2 == crypto_secretstream_xchacha20poly1305_tag_final()

suite "padding":

  test "small":
    let padded = sodium_pad("something\0\128\0", 12)
    check padded.len mod 12 == 0
    check sodium_unpad(padded, 12) == "something\0\128\0"

  test "message larger than block":
    let msg = "a".repeat(257)
    let padded = sodium_pad(msg, 32)
    check padded.len mod 32 == 0
    check sodium_unpad(padded, 32) == msg

  test "all message sizes":
    for i in 1..2049:
      checkpoint($i)
      let msg = "a".repeat(i)
      let padded = sodium_pad(msg, 32)
      check padded.len mod 32 == 0
      check sodium_unpad(padded, 32) == msg

  test "all block sizes":
    for i in 1..2049:
      checkpoint($i)
      let msg = "a".repeat(125)
      let padded = sodium_pad(msg, i)
      check padded.len mod i == 0
      check sodium_unpad(padded, i) == msg
