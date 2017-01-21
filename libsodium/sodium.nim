#
# Libsodium18 wrapper for Nim
#
# 2016 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3, see LICENSE file
#
#
## Libsodium18 wrapper
##
## Memory-unsafe operations are not exposed.
##
## Please always refer to libsodium upstream documentation and ensure that you
## are using the library in a secure way.

{.deadCodeElim: on.}

import strutils

import sodium_sizes

when defined(windows):
  const libsodium_fn* = "libsodium.dll"
elif defined(macosx):
  const libsodium_fn* = "libsodium.dylib"
else:
  const libsodium_fn* = "libsodium.so.18"


{.pragma: sodium_import, importc, dynlib: libsodium_fn.}


# helpers

template cpt[I](target: array[I, char]): ptr cuchar =
  cast[ptr cuchar](cstring(target))

template cpt(target: string): ptr cuchar =
  cast[ptr cuchar](cstring(target))

template cpsize[I](target: array[I, char]): csize =
  csize(target.len)

template cpsize(target: string): csize =
  csize(target.len)

template zeroed*(length: int): string =
  ## Return a zeroed string
  repeat('\0', length)

type SodiumError* = object of Exception

template check_rc(rc: cint) =
  ## Expect return code to be 0, raise an exception otherwise
  if rc != 0:
    raise newException(SodiumError, "return code: $#" % $rc)



# https://download.libsodium.org/doc/helpers/memory_management.html


# https://download.libsodium.org/doc/generating_random_data/index.html


proc randombytes_buf(
  buf: ptr cuchar,
  size: csize,
) {.sodium_import.}

proc randombytes*(size: int): string =
  result = newString size
  let o = cpt result
  randombytes_buf(o, csize(size))

proc randombytes*[I](arr: var array[I, char]) =
  randombytes_buf(cpt arr, len(arr))

proc randombytes_stir*() {.sodium_import.}
  ## Reseeds the pseudorandom number generator - if supported.





# https://download.libsodium.org/doc/helpers/index.html


proc sodium_memcmp(
  b1: ptr cuchar,
  b2: ptr cuchar,
  blen: csize,
):cint {.sodium_import.}

proc memcmp*(a, b: string): bool =
  ## Constant-time test for equality
  if a.len != b.len:
    return false
  let
    b1 = cpt a
    b2 = cpt b
    blen = cpsize a
    rc = sodium_memcmp(b1, b2, blen)
  return rc == 0

proc sodium_is_zero(
  n: ptr cuchar,
  n_len: csize,
):cint {.sodium_import.}

proc is_zero*(data: string): bool =
  ## Returns true if a byte string contains only zeros.
  ## Time constant for a given length.
  let
    n = cpt data
    n_len = cpsize data
    rc = sodium_is_zero(n, n_len)
  return rc == 1


proc sodium_bin2hex(
  hex: ptr cuchar,
  hex_maxlen: csize;
  bin: ptr cuchar,
  bin_len: csize,
):cint {.sodium_import.}

proc bin2hex*[I](data: array[I, char]): string =
  result = newString data.len * 2 + 1
  let
    hex = cpt result
    hex_maxlen = cpsize result
    bin = cpt data
    bin_len = cpsize data
  discard sodium_bin2hex(hex, hex_maxlen, bin, bin_len)
  result = result[0..(data.len * 2 - 1)]

proc bin2hex*(data: string): string =
  result = newString data.len * 2 + 1
  let
    hex = cpt result
    hex_maxlen = cpsize result
    bin = cpt data
    bin_len = cpsize data
  discard sodium_bin2hex(hex, hex_maxlen, bin, bin_len)
  result = result[0..(data.len * 2 - 1)]


proc sodium_hex2bin(
  bin: ptr cuchar,
  bin_maxlen: csize,
  hex: ptr cchar,
  hex_len: csize,
  #
  ignore: ptr cchar,
  bin_len: ptr csize,
  hex_end: ptr ptr cchar
):cint {.sodium_import.}


proc hex2bin*(data: string, ignore=""): string =
  result = newString data.len div 2
  let
    bin = cpt result
    bin_maxlen = cpsize result
    hex = cpt data
    hex_len = cpsize data
    ig = cpt ignore
  discard sodium_hex2bin(bin, bin_maxlen, hex, hex_len, ig, nil, nil)


type
  Ed25519Pk* = array[crypto_sign_ed25519_PUBLICKEYBYTES, char]
  Ed25519Sk* = array[crypto_sign_ed25519_SECRETKEYBYTES, char]
  Curve25519Pk* = array[crypto_scalarmult_curve25519_BYTES, char]
  Curve25519Sk* = array[crypto_scalarmult_curve25519_BYTES, char]


# Authenticated encryption
# https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html

type
  SecretBoxKey*   = array[crypto_secretbox_KEYBYTES, char]
  SecretBoxNonce* = array[crypto_secretbox_NONCEBYTES, char]

proc crypto_secretbox_easy(
  c: ptr cuchar,
  m: ptr cuchar,
  mlen: csize,
  n: ptr cuchar,
  k: ptr cuchar,
):cint {.sodium_import.}

proc crypto_secretbox_easy*(key: SecretBoxKey,
                            nonce: SecretBoxNonce,
                            msg: string): string =
  ## Encrypt + sign a variable len string with a preshared key
  result = newString msg.len + crypto_secretbox_MACBYTES
  let
    c_ciphertext = cpt result
    cmsg = cpt msg
    mlen = cpsize msg
    cnon = cpt nonce
    ckey = cpt key
  let rc = crypto_secretbox_easy(c_ciphertext, cmsg, mlen, cnon, ckey)
  check_rc rc

proc crypto_secretbox_easy*(key: SecretBoxKey, msg: string): string =
  ## Encrypt + sign a variable len string with a preshared key
  ## A random nonce is generated from /dev/urandom and prepended to the output

  let nonce = randombytes(crypto_secretbox_NONCEBYTES)
  var
    cnonce = cpt nonce

  let
    ciphertext = newString msg.len + crypto_secretbox_MACBYTES
    c_ciphertext = cpt ciphertext
    cmsg = cpt msg
    mlen = cpsize msg
    ckey = cpt key
  let rc = crypto_secretbox_easy(c_ciphertext, cmsg, mlen, cnonce, ckey)
  check_rc rc
  return nonce & ciphertext


proc crypto_secretbox_open_easy(
  decrypted: ptr cuchar,
  c: ptr cuchar,
  clen: csize,
  n: ptr cuchar,
  k: ptr cuchar,
):cint {.sodium_import.}

proc crypto_secretbox_open_easy*(key: SecretBoxKey,
                                 nonce: SecretBoxNonce,
                                 ciphertext: string): string =
  ## Decrypt + sign a variable len string with a preshared key
  assert ciphertext.len > crypto_secretbox_MACBYTES
  result = newString ciphertext.len - crypto_secretbox_MACBYTES
  let
    c_decrypted = cpt result
    c_ciphertext = cpt ciphertext
    ciphertext_len = cpsize ciphertext
    c_nonce = cpt nonce
    c_key = cpt key
  let rc = crypto_secretbox_open_easy(
    c_decrypted,
    c_ciphertext,
    ciphertext_len,
    c_nonce,
    c_key
  )
  if rc != 0:
    return nil

proc crypto_secretbox_open_easy*(key: SecretBoxKey, bulk: string): string =
  ## Decrypt + sign a variable len string with a preshared key
  ## A nonce is expected at the beginning of the input string
  let nonce_size = crypto_secretbox_NONCEBYTES
  assert bulk.len >= nonce_size
  let
    nonce = bulk[0..nonce_size-1]
    ciphertext = bulk[nonce_size..^1]

  assert nonce.len == nonce_size
  assert bulk.len == nonce_size + ciphertext.len

  result = newString ciphertext.len - crypto_secretbox_MACBYTES
  let
    c_decrypted = cpt result
    c_ciphertext = cpt ciphertext
    ciphertext_len = cpsize ciphertext
    c_nonce = cpt nonce
    c_key = cpt key
  let rc = crypto_secretbox_open_easy(c_decrypted, c_ciphertext, ciphertext_len, c_nonce, c_key)
  check_rc rc


# Secret-key authentication
# https://download.libsodium.org/doc/secret-key_cryptography/secret-key_authentication.html

type
  AuthKey* = array[crypto_auth_KEYBYTES, char]
  AuthTag* = array[crypto_auth_BYTES, char]

proc crypto_auth(
  mac: ptr cuchar,
  msg: ptr cuchar,
  msg_len: csize,
  key: ptr cuchar,
):cint {.sodium_import.}

proc crypto_auth*(message: string, key: AuthKey): AuthTag =
  let
    mac = cpt result
    msg = cpt message
    msg_len = cpsize message
    k = cpt key
    rc = crypto_auth(mac, msg, msg_len, k)
  check_rc rc


proc crypto_auth_verify(
  mac: ptr cuchar,
  msg: ptr cuchar,
  msg_len: csize,
  key: ptr cuchar,
):cint {.sodium_import.}

proc crypto_auth_verify*(mac: AuthTag,
                         message: string,
                         key: AuthKey): bool =
  let
    tag = cpt mac
    msg = cpt message
    msg_len = cpsize message
    k = cpt key
    rc = crypto_auth_verify(tag, msg, msg_len, k)
  rc == 0

# https://download.libsodium.org/doc/secret-key_cryptography/aead.html
# https://download.libsodium.org/doc/secret-key_cryptography/original_chacha20-poly1305_construction.html
# https://download.libsodium.org/doc/secret-key_cryptography/ietf_chacha20-poly1305_construction.html
# https://download.libsodium.org/doc/secret-key_cryptography/aes-256-gcm.html
#
# https://download.libsodium.org/doc/secret-key_cryptography/aes-gcm_with_precomputation.html


# Public-key authenticated encryption
# https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html


type
  BoxPublicKey* = array[crypto_box_PUBLICKEYBYTES, char]
  BoxSecretKey* = array[crypto_box_SECRETKEYBYTES, char]
  BoxNonce* = array[crypto_box_NONCEBYTES, char]
  BoxSeed* = array[crypto_box_SEEDBYTES, char]


proc crypto_box_keypair(
  pk: ptr cuchar,
  sk: ptr cuchar
):cint {.sodium_import.}

proc crypto_box_keypair*(): (BoxPublicKey, BoxSecretKey) =
  let
    pk = cpt result[0]
    sk = cpt result[1]
  let rc = crypto_box_keypair(pk, sk)
  check_rc rc


proc crypto_box_seed_keypair(
  pk: ptr cuchar,
  sk: ptr cuchar,
  seed: ptr cuchar
):cint {.sodium_import.}

proc crypto_box_seed_keypair*(seed: BoxSeed):
                             (BoxPublicKey, BoxSecretKey) =
  let
    pk = cpt result[0]
    sk = cpt result[1]
    seed = cpt seed
  let rc = crypto_box_seed_keypair(pk, sk, seed)
  check_rc rc


proc crypto_scalarmult_base(
  pk: ptr cuchar,
  sk: ptr cuchar
):cint {.sodium_import.}

proc crypto_scalarmult_base*(secret: BoxSecretKey): BoxPublicKey =
  let
    pk = cpt result
    sk = cpt secret
  let rc = crypto_scalarmult_base(pk, sk)
  check_rc rc


proc crypto_box_easy(
  c: ptr cuchar,
  m: ptr cuchar,
  mlen: csize,
  n: ptr cuchar,
  pk: ptr cuchar,
  sk: ptr cuchar,
):cint {.sodium_import.}

proc crypto_box_easy*(message: string,
                      nonce: BoxNonce,
                      public_key: BoxPublicKey,
                      secret_key: BoxSecretKey): string =
  result = newString message.len + crypto_box_MACBYTES
  let
    c = cpt result
    m = cpt message
    mlen = cpsize message
    n = cpt nonce
    pk = cpt public_key
    sk = cpt secret_key
    rc = crypto_box_easy(c, m, mlen, n, pk, sk)
  check_rc rc


proc crypto_box_open_easy(
  c: ptr cuchar,
  m: ptr cuchar,
  mlen: csize,
  n: ptr cuchar,
  pk: ptr cuchar,
  sk: ptr cuchar,
):cint {.sodium_import.}

proc crypto_box_open_easy*(ciphertext: string,
                           nonce: BoxNonce,
                           public_key: BoxPublicKey,
                           secret_key: BoxSecretKey): string =
  result = newString ciphertext.len - crypto_box_MACBYTES
  let
    m = cpt result
    c = cpt ciphertext
    clen = cpsize ciphertext
    n = cpt nonce
    pk = cpt public_key
    sk = cpt secret_key
  let rc = crypto_box_open_easy(m, c, clen, n, pk, sk)
  if rc != 0:
    result = nil



# Public-key signatures
# https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html


type
  SignPublicKey* = array[crypto_sign_PUBLICKEYBYTES, char]
  SignSecretKey* = array[crypto_sign_SECRETKEYBYTES, char]
  SignDetached* = array[crypto_sign_BYTES, char]
  SignSeed* = array[crypto_sign_SEEDBYTES, char]


proc crypto_sign_keypair(
  pk: ptr cuchar,
  sk: ptr cuchar
):cint {.sodium_import.}

proc crypto_sign_keypair*(): (SignPublicKey, SignSecretKey) =
  ## Generate a random public and secret key
  let
    pk = cpt result[0]
    sk = cpt result[1]
    rc = crypto_sign_keypair(pk, sk)
  check_rc rc


proc crypto_sign_seed_keypair(
  pk: ptr cuchar,
  sk: ptr cuchar,
  seed: ptr cuchar
):cint {.sodium_import.}

proc crypto_sign_seed_keypair*(seed: SignSeed):
                              (SignPublicKey, SignSecretKey) =
  ## Deterministically generate a public and secret key from a seed
  let
    pk = cpt result[0]
    sk = cpt result[1]
    s = cpt seed
    rc = crypto_sign_seed_keypair(pk, sk, s)
  check_rc rc


proc crypto_sign_detached(
   sig: ptr cuchar,
   siglen: ptr csize,
   m: ptr cuchar,
   mlen: csize,
   sk: ptr cuchar
):cint {.sodium_import.}

proc crypto_sign_detached*(secret_key: SignSecretKey,
                           message: string): SignDetached =
  let
    sk = cpt secret_key
    sig = cpt result
    msg = cpt message
    msg_len = cpsize message

  let rc = crypto_sign_detached(sig, nil, msg, msg_len, sk)
  check_rc rc


proc crypto_sign_verify_detached(
  sig: ptr cuchar,
  m: ptr cuchar,
  mlen: csize,
  pk: ptr cuchar
):cint {.sodium_import.}

proc crypto_sign_verify_detached*(public_key: SignPublicKey,
                                  message: string,
                                  signature: SignDetached): bool =
  let
    pk = cpt public_key
    sig = cpt signature
    msg = cpt message
    msg_len = cpsize message
  let rc = crypto_sign_verify_detached(sig, msg, msg_len, pk)
  rc == 0


proc crypto_sign_ed25519_sk_to_seed(
  seed: ptr cuchar,
  sk: ptr cuchar
):cint {.sodium_import.}

proc crypto_sign_ed25519_sk_to_seed*(secret_key: SignSecretKey):
                                    SignSeed =
  ## Extract the seed from a secret key
  let
    sk = cpt secret_key
    seed = cpt result
    rc = crypto_sign_ed25519_sk_to_seed(seed, sk)
  check_rc rc


proc crypto_sign_ed25519_sk_to_pk(
  pk: ptr cuchar,
  sk: ptr cuchar
):cint {.sodium_import.}

proc crypto_sign_ed25519_sk_to_pk*(secret_key: SignSecretKey):
                                  SignPublicKey =
  ## Extract the public key from a secret key
  let
    sk = cpt secret_key
    pk = cpt result
    rc = crypto_sign_ed25519_sk_to_pk(pk, sk)
  check_rc rc


# Sealed boxes
# https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html


proc crypto_box_seal(
  c: ptr cuchar;
  m: ptr cuchar,
  mlen: csize,
  pk: ptr cuchar,
):cint {.sodium_import.}

proc crypto_box_seal*(message: string,
                      public_key: BoxPublicKey): string =
  ## Encrypt a message using the receiver public key
  result = newString(message.len + crypto_box_SEALBYTES)
  let
    pk = cpt public_key
    msg = cpt message
    msg_len = cpsize message
    c = cpt result
    rc = crypto_box_seal(c, msg, msg_len, pk)
  if rc != 0:
    result = nil


proc crypto_box_seal_open(
  m: ptr cuchar,
  c: ptr cuchar,
  clen: csize,
  pk: ptr cuchar,
  sk: ptr cuchar,
):cint {.sodium_import.}

proc crypto_box_seal_open*(ciphertext: string,
                           public_key: BoxPublicKey,
                           secret_key: BoxSecretKey): string =
  ## Decrypt a ciphertext using a public and secret key
  assert ciphertext.len > crypto_box_SEALBYTES
  result = newString(ciphertext.len - crypto_box_SEALBYTES)
  let
    m = cpt result
    c = cpt ciphertext
    clen = cpsize ciphertext
    pk = cpt public_key
    sk = cpt secret_key
    rc = crypto_box_seal_open(m, c, clen, pk, sk)
  if rc != 0:
    result = nil


# Generic hashing
# https://download.libsodium.org/doc/hashing/generic_hashing.html


proc crypto_generichash(
  h: ptr cuchar,
  hlen: csize,
  m: ptr cuchar,
  mlen: csize,
  key: ptr cuchar,
  keylen: csize,
):cint {.sodium_import.}

proc crypto_generichash*(data: string,
                         hashlen: int = crypto_generichash_BYTES,
                         key: string = nil): string =
  ## Generate a hash of "data" of len "hashlen" using an optional key
  ## hashlen defaults to crypto_generichash_BYTES
  if key != nil:
    doAssert(crypto_generichash_KEYBYTES_MIN <= key.len)
    doAssert(key.len <= crypto_generichash_KEYBYTES_MAX)

  result = newString hashlen
  let
    h = cpt result
    hlen =
      if hashlen == -1: csize(crypto_generichash_BYTES)
      else: csize(hashlen)

    m = cpt data
    mlen = cpsize data
    k =
      if key == nil: nil
      else: cpt key

    klen = cpsize key
    rc = crypto_generichash(h, hlen, m, mlen, k, klen)
  check_rc rc


type GenericHash* = tuple
  state: string
  out_len: int

proc crypto_generichash_init(
  state: ptr cuchar,
  key: ptr cuchar,
  keylen: csize,
  outlen: csize
):cint {.sodium_import.}

proc crypto_generichash_update(
  state: ptr cuchar,
  data: ptr cuchar,
  data_len: csize
):cint {.sodium_import.}

proc crypto_generichash_final(
  state: ptr cuchar,
  output: ptr cuchar,
  out_len: csize,
):cint {.sodium_import.}


proc new_generic_hash*(key: string,
                       out_len: int = crypto_generichash_BYTES): GenericHash =
  ## Create a new multipart hash, returns a GenericHash.
  ## The GenericHash is to be updated with .update()
  ## Upon calling .finalize() on it it will return a
  ## hash value of length "out_len"
  if key != nil:
    doAssert crypto_generichash_KEYBYTES_MIN.int <= key.len
    doAssert key.len <= crypto_generichash_KEYBYTES_MAX.int
  doAssert crypto_generichash_BYTES_MIN.int <= out_len
  doAssert out_len <= crypto_generichash_BYTES_MAX.int

  result = (newString crypto_generichash_stateBYTES(), out_len)
  let
    state = cpt result.state
    k =
      if key == nil: nil
      else: cpt key
    klen = cpsize key
    olen = csize out_len
    rc = crypto_generichash_init(state, k, klen, olen)
  check_rc rc

proc update*(self: GenericHash, data: string) =
  ## Update the multipart hash with more data
  let
    s = cpt self.state
    d = cpt data
    d_len = cpsize data
    rc = crypto_generichash_update(s, d, d_len)
  check_rc rc

proc finalize*(self: GenericHash): string =
  ## Finish the multipart hash and return the hash value as a string
  result = newString self.out_len
  let
    s = cpt self.state
    h = cpt result
    h_len = csize self.out_len
    rc = crypto_generichash_final(s, h, h_len)
  check_rc rc
  assert h.len == self.out_len


# Short-input hashing
# https://download.libsodium.org/doc/hashing/short-input_hashing.html

type
  ShortHashKey* = array[crypto_shorthash_KEYBYTES, char]
  ShortHash* = array[crypto_shorthash_BYTES, char]

proc crypto_shorthash(
  o: ptr cuchar,
  data: ptr cuchar,
  data_len: csize,
  k: ptr cuchar,
):cint {.sodium_import.}

proc crypto_shorthash*(data: string, key: ShortHashKey): ShortHash =
  ## Hash optimized for short inputs
  let
    o = cpt result
    d = cpt data
    d_len = cpsize data
    k = cpt key
    rc = crypto_shorthash(o, d, d_len, k)
  check_rc rc

proc generate_key_for_short_hash*(): ShortHashKey =
  randombytes result


# Diffie-Hellman function
# https://download.libsodium.org/doc/advanced/scalar_multiplication.html

proc crypto_scalarmult(
  q: ptr cuchar,
  n: ptr cuchar,
  p: ptr cuchar,
):cint {.sodium_import.}

proc crypto_scalarmult*(secret_key: Curve25519Sk,
                        public_key: Curve25519Pk):
                        array[crypto_scalarmult_BYTES, char] =
  ## Compute a shared secret given a secret key and another user's public key.
  ## The Sodium library recommends *not* using the shared secred directly,
  ## rather a hash of the shared secred concatenated with the public keys from
  ## both users
  let
    q = cpt result  # output
    n = cpt secret_key  # secret key
    p = cpt public_key  # public key
    rc = crypto_scalarmult(q, n, p)
  check_rc rc


# Secret-key single-message authentication using Poly1305
# https://download.libsodium.org/doc/advanced/poly1305.html

type
  OneTimeAuthKey* = array[crypto_onetimeauth_KEYBYTES, char]
  OneTimeAuthTag* = array[crypto_onetimeauth_BYTES, char]


proc crypto_onetimeauth(
  o: ptr cuchar,
  msg: ptr cuchar,
  msg_len: csize,
  key: ptr cuchar
):cint {.sodium_import.}

proc crypto_onetimeauth*(message: string, key: OneTimeAuthKey): OneTimeAuthTag =
  ## One-time authentication using Poly1305
  ## Warning: Use unpredictable, secret, unique keys
  let
    o = cpt result
    msg = cpt message
    msg_len = cpsize message
    k = cpt key
    rc = crypto_onetimeauth(o, msg, msg_len, k)
  check_rc rc


proc crypto_onetimeauth_verify(
  o: ptr cuchar,
  msg: ptr cuchar,
  msg_len: csize,
  key: ptr cuchar
):cint {.sodium_import.}

proc crypto_onetimeauth_verify*(tok: OneTimeAuthTag,
                                message: string,
                                key: OneTimeAuthKey): bool =
  ## Verify onetimeauth
  let
    o = cpt tok
    msg = cpt message
    msg_len = cpsize message
    k = cpt key
    rc = crypto_onetimeauth_verify(o, msg, msg_len, k)
  rc == 0


# Ed25519 to Curve25519 keys conversion
# https://download.libsodium.org/doc/advanced/ed25519-curve25519.html

proc crypto_sign_ed25519_pk_to_curve25519(
  curve25519_pk: ptr cuchar,
  ed25519_pk: ptr cuchar
):cint {.sodium_import.}

proc crypto_sign_ed25519_pk_to_curve25519*(pk: Ed25519Pk): Curve25519Pk =
  let
    c = cpt result
    e = cpt pk
  check_rc crypto_sign_ed25519_pk_to_curve25519(c, e)

proc crypto_sign_ed25519_sk_to_curve25519(
  curve25519_sk: ptr cuchar,
  ed25519_sk: ptr cuchar
):cint {.sodium_import.}

proc crypto_sign_ed25519_sk_to_curve25519*(sk: Ed25519Sk): Curve25519Sk =
  let
    c = cpt result
    e = cpt sk
  check_rc crypto_sign_ed25519_sk_to_curve25519(c, e)

