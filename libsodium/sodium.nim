# 2017 Federico Ceratto <federico.ceratto@gmail.com>
# Released under MPL-2.0, see LICENSE file
#
## Libsodium18/23 wrapper
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
  const libsodium_fn* = "libsodium.so(.18|.23)"


{.pragma: sodium_import, importc, dynlib: libsodium_fn.}


# helpers

type cptr* = ptr char

template cpt(target: string): untyped =
  cast[cptr](cstring(target))

template cpsize(target: string): untyped =
  csize_t(target.len)

template culen(target: string): untyped =
  culonglong(target.len)

template zeroed*(length: int): untyped =
  ## Return a zeroed string
  repeat('\0', length)

type SodiumError* = object of Exception

template check_rc(rc: cint): untyped =
  ## Expect return code to be 0, raise an exception otherwise
  if rc != 0:
    raise newException(SodiumError, "return code: $#" % $rc)


# Initialization - https://download.libsodium.org/doc/quickstart

proc sodium_init*(): cint {.sodium_import.}
  ## Initialize libsodium. Returns 0 for success, 1 if it was already initialized
  ## and -1 on failure.
  ##
  ## It is called automatically at runtime unless `no_sodium_autoinit` is defined.

when not defined(no_sodium_autoinit):
  doAssert sodium_init() >= 0, "Libsodium failed to initialize"


# https://download.libsodium.org/doc/helpers/memory_management.html

# https://download.libsodium.org/doc/generating_random_data/index.html


proc randombytes(
  buf: cptr,
  size: culonglong,
) {.sodium_import.}

proc randombytes_random*(): uint32 {.sodium_import.}
  ## Returns an unpredictable value between 0 and 0xffffffff (included).

proc randombytes_uniform*(upper_bound: uint32): uint32 {.sodium_import.}
  ## Returns an unpredictable value between 0 and ``upper_bound`` (excluded)
  ## with uniform distribution

proc randombytes*(size: int): string =
  result = newString size
  let o = cpt result
  randombytes(o, culonglong(size))
  assert result.len == size

proc randombytes_stir*() {.sodium_import.}
  ## Reseeds the pseudorandom number generator - if supported.





# https://download.libsodium.org/doc/helpers/index.html


proc sodium_memcmp(
  b1: cptr,
  b2: cptr,
  blen: csize_t,
): cint {.sodium_import.}

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

# Not exposed
proc sodium_compare(
  b1: cptr,
  b2: cptr,
  blen: csize_t,
): cint {.sodium_import.}

proc sodium_is_zero(
  n: cptr,
  n_len: csize_t,
): cint {.sodium_import.}

proc is_zero*(data: string): bool =
  ## Returns true if a byte string contains only zeros.
  ## Time constant for a given length.
  let
    n = cpt data
    n_len = cpsize data
    rc = sodium_is_zero(n, n_len)
  return rc == 1


proc sodium_bin2hex(
  hex: cptr,
  hex_maxlen: csize_t;
  bin: cptr,
  bin_len: csize_t,
): cint {.sodium_import.}

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
  bin: cptr,
  bin_maxlen: csize_t,
  hex: cptr,
  hex_len: csize_t,
  #
  ignore: cptr,
  bin_len: ptr csize_t,
  hex_end: ptr cptr
): cint {.sodium_import.}


proc hex2bin*(data: string, ignore = ""): string =
  result = newString data.len div 2
  let
    bin = cpt result
    bin_maxlen = cpsize result
    hex = cpt data
    hex_len = cpsize data
    ig = cpt ignore
  discard sodium_hex2bin(bin, bin_maxlen, hex, hex_len, ig, nil, nil)


# Authenticated encryption
# https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html


#void crypto_secretbox_keygen(unsigned char k[crypto_secretbox_KEYBYTES]);

proc crypto_secretbox_keygen(k: cptr) {.sodium_import.}

proc crypto_secretbox_keygen*(): string =
  ## Generates a random key of length `crypto_secretbox_KEYBYTES`
  result = newString crypto_secretbox_KEYBYTES()
  let c_key = cpt result
  crypto_secretbox_keygen(c_key)

proc crypto_secretbox_easy(
  c: cptr,
  m: cptr,
  mlen: culonglong,
  n: cptr,
  k: cptr,
): cint {.sodium_import.}

proc crypto_secretbox_easy*(key: string, msg: string): string =
  ## Encrypt + sign a variable len string with a preshared key
  ## A random nonce is generated from /dev/urandom and prepended to the output
  runnableExamples:
    let
      msg = "hello there"
      key = crypto_secretbox_keygen()
      ciphertext = crypto_secretbox_easy(key, msg)
      decrypted = crypto_secretbox_open_easy(key, ciphertext)
    assert decrypted == msg

  assert key.len == crypto_secretbox_KEYBYTES()
  let nonce = randombytes(crypto_secretbox_NONCEBYTES().int)
  var
    cnonce = cpt nonce

  let
    ciphertext = newString msg.len + crypto_secretbox_MACBYTES()
    c_ciphertext = cpt ciphertext
    cmsg = cpt msg
    mlen = culen msg
    ckey = cpt key
  let rc = crypto_secretbox_easy(c_ciphertext, cmsg, mlen, cnonce, ckey)
  check_rc rc
  return nonce & ciphertext


proc crypto_secretbox_open_easy(
  decrypted: cptr,
  c: cptr,
  clen: culonglong,
  n: cptr,
  k: cptr,
): cint {.sodium_import.}

proc crypto_secretbox_open_easy*(key: string, bulk: string): string =
  ## Decrypt + sign a variable len string with a preshared key
  ## A nonce is expected at the beginning of the input string
  let nonce_size = crypto_secretbox_NONCEBYTES().int
  assert key.len == crypto_secretbox_KEYBYTES()
  assert bulk.len >= nonce_size
  let
    nonce = bulk[0..nonce_size-1]
    ciphertext = bulk[nonce_size..^1]

  assert nonce.len == nonce_size
  assert bulk.len == nonce_size + ciphertext.len

  let
    decrypted = newString ciphertext.len - crypto_secretbox_MACBYTES()
    c_decrypted = cpt decrypted
    c_ciphertext = cpt ciphertext
    ciphertext_len = culen ciphertext
    c_nonce = cpt nonce
    c_key = cpt key
  let rc = crypto_secretbox_open_easy(c_decrypted, c_ciphertext, ciphertext_len,
      c_nonce, c_key)
  check_rc rc

  return decrypted


# Secret-key authentication (HMAC)
# https://download.libsodium.org/doc/secret-key_cryptography/secret-key_authentication.html

proc crypto_auth(
  mac: cptr,
  msg: cptr,
  msg_len: culonglong,
  key: cptr,
): cint {.sodium_import.}

proc crypto_auth*(message, key: string): string =
  result = newString crypto_auth_BYTES()
  assert key.len == crypto_auth_keybytes()
  let
    mac = cpt result
    msg = cpt message
    msg_len = culen message
    k = cpt key
    rc = crypto_auth(mac, msg, msg_len, k)
  check_rc rc


proc crypto_auth_verify(
  mac: cptr,
  msg: cptr,
  msg_len: culonglong,
  key: cptr,
): cint {.sodium_import.}

proc crypto_auth_verify*(mac, message, key: string): bool =
  assert key.len == crypto_auth_keybytes()
  assert mac.len == crypto_auth_bytes()
  let
    tag = cpt mac
    msg = cpt message
    msg_len = culen message
    k = cpt key
    rc = crypto_auth_verify(tag, msg, msg_len, k)

  return rc == 0

# https://download.libsodium.org/doc/secret-key_cryptography/aead.html
# https://download.libsodium.org/doc/secret-key_cryptography/original_chacha20-poly1305_construction.html
# https://download.libsodium.org/doc/secret-key_cryptography/ietf_chacha20-poly1305_construction.html
# https://download.libsodium.org/doc/secret-key_cryptography/aes-256-gcm.html
#
# https://download.libsodium.org/doc/secret-key_cryptography/aes-gcm_with_precomputation.html

# https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html


#proc verify_message*(key: string, msg: string, signature: string) =
#  ## verify a message signed using ed25519
#  ## if the signature is not provided, it is assumed that it is found at the
#  ## beginning of the message
#  discard
#
#
#proc sign_message*(key, message: string): string =
#  ## sign a message using ed25519
#  discard


# Public-key authenticated encryption
# https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html


type
  CryptoBoxPublicKey = string
  CryptoBoxSecretKey = string

template cpt(target: CryptoBoxPublicKey): untyped =
  cast[cptr](cstring(target))


proc crypto_box_keypair(
  pk: cptr,
  sk: cptr
): cint {.sodium_import.}

proc crypto_box_keypair*(): (CryptoBoxPublicKey, CryptoBoxSecretKey) =
  result[0] = newString crypto_box_PUBLICKEYBYTES()
  result[1] = newString crypto_box_SECRETKEYBYTES()
  let
    pk = cpt result[0]
    sk = cpt result[1]
  let rc = crypto_box_keypair(pk, sk)
  check_rc rc

#TODO crypto_box_seed_keypair crypto_scalarmult_base

proc crypto_box_easy(
  c: cptr,
  m: cptr,
  mlen: culonglong,
  n: cptr,
  pk: cptr,
  sk: cptr,
): cint {.sodium_import.}

proc crypto_box_easy*(message, nonce: string, public_key: CryptoBoxPublicKey,
    secret_key: CryptoBoxSecretKey): string =
  result = newString message.len + crypto_box_MACBYTES()
  doAssert nonce.len == crypto_box_NONCEBYTES()
  let
    c = cpt result
    m = cpt message
    mlen = culen message
    n = cpt nonce
    pk = cpt public_key
    sk = cpt secret_key
    rc = crypto_box_easy(c, m, mlen, n, pk, sk)
  check_rc rc

proc crypto_box_open_easy(
  c: cptr,
  m: cptr,
  mlen: culonglong,
  n: cptr,
  pk: cptr,
  sk: cptr,
): cint {.sodium_import.}

proc crypto_box_open_easy*(ciphertext, nonce: string,
    public_key: CryptoBoxPublicKey, secret_key: CryptoBoxSecretKey): string =
  doAssert nonce.len == crypto_box_NONCEBYTES()
  result = newString ciphertext.len - crypto_box_MACBYTES()
  let
    m = cpt result
    c = cpt ciphertext
    clen = culen ciphertext
    n = cpt nonce
    pk = cpt public_key
    sk = cpt secret_key
    rc = crypto_box_open_easy(m, c, clen, n, pk, sk)
  check_rc rc



# Public-key signatures
# https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html



type
  PublicKey = string
  SecretKey = string

proc crypto_sign_keypair(
  pk: cptr,
  sk: cptr
): cint {.sodium_import.}

proc crypto_sign_keypair*(): (PublicKey, SecretKey) =
  ## Generate a random public and secret key
  result = (newString crypto_sign_PUBLICKEYBYTES(),
      newString crypto_sign_SECRETKEYBYTES())
  let
    pk = cpt result[0]
    sk = cpt result[1]
    rc = crypto_sign_keypair(pk, sk)
  check_rc rc


proc crypto_sign_seed_keypair(
  pk: cptr,
  sk: cptr,
  seed: cptr
): cint {.sodium_import.}

proc crypto_sign_seed_keypair*(seed: string): (PublicKey, SecretKey) =
  ## Deterministically generate a public and secret key from a seed
  assert seed.len == crypto_sign_SEEDBYTES()
  result = (newString crypto_sign_PUBLICKEYBYTES(),
            newString crypto_sign_SECRETKEYBYTES())
  let
    pk = cpt result[0]
    sk = cpt result[1]
    s = cpt seed
    rc = crypto_sign_seed_keypair(pk, sk, s)
  check_rc rc


proc crypto_sign_detached(
   sig: cptr,
   siglen: ptr culonglong,
   m: cptr,
   mlen: culonglong,
   sk: cptr
): cint {.sodium_import.}

proc crypto_sign_detached*(secret_key: SecretKey, message: string): string =
  result = newString crypto_sign_BYTES()
  let
    sk = cpt secret_key
    sig = cpt result
    msg = cpt message
    msg_len = culen message

  let rc = crypto_sign_detached(sig, nil, msg, msg_len, sk)
  check_rc rc
  assert result.len == crypto_sign_BYTES()


proc crypto_sign_verify_detached(
  sig: cptr,
  m: cptr,
  mlen: culonglong,
  pk: cptr
): cint {.sodium_import.}

proc crypto_sign_verify_detached*(public_key: PublicKey, message,
    signature: string) =
  assert signature.len == crypto_sign_BYTES()
  assert public_key.len == crypto_sign_PUBLICKEYBYTES()
  let
    pk = cpt public_key
    sig = cpt signature
    msg = cpt message
    msg_len = culen message
  let rc = crypto_sign_verify_detached(sig, msg, msg_len, pk)
  check_rc rc


proc crypto_sign_ed25519_sk_to_seed(
  seed: cptr,
  sk: cptr
): cint {.sodium_import.}

proc crypto_sign_ed25519_sk_to_seed*(secret_key: SecretKey): string =
  ## Extract the seed from a secret key
  assert secret_key.len == crypto_sign_SECRETKEYBYTES()
  result = newString crypto_sign_SEEDBYTES()
  let
    sk = cpt secret_key
    seed = cpt result
    rc = crypto_sign_ed25519_sk_to_seed(seed, sk)
  check_rc rc


proc crypto_sign_ed25519_sk_to_pk(
  pk: cptr,
  sk: cptr
): cint {.sodium_import.}

proc crypto_sign_ed25519_sk_to_pk*(secret_key: SecretKey): PublicKey =
  ## Extract the public key from a secret key
  assert secret_key.len == crypto_sign_SECRETKEYBYTES()
  result = newString crypto_sign_PUBLICKEYBYTES()
  let
    sk = cpt secret_key
    pk = cpt result
    rc = crypto_sign_ed25519_sk_to_pk(pk, sk)
  check_rc rc


proc crypto_sign(
  sm: cptr,
  smlen_p: ptr culonglong,
  m: cptr,
  mlen: culonglong,
  sk: cptr,
): cint {.sodium_import.}

proc crypto_sign*(secret_key: SecretKey, message: string): string =
  ## Sign a message, combining it with the message
  assert secret_key.len == crypto_sign_SECRETKEYBYTES()
  result = newString(crypto_sign_bytes() + message.len)
  let
    sk = cpt secret_key
    sm = cpt result
    m = cpt message
    mlen = culen message
    rc = crypto_sign(sm, nil, m, mlen, sk)
  check_rc rc


proc crypto_sign_open(
  m: cptr,
  mlen_p: ptr culonglong,
  sm: cptr,
  smlen: culonglong,
  pk: cptr,
): cint {.sodium_import.}

proc crypto_sign_open*(public_key: PublicKey, signed_message: string): string =
  ## Verify a signed combined message, returning the message on success
  assert public_key.len == crypto_sign_PUBLICKEYBYTES()
  result = newString(signed_message.len - crypto_sign_bytes())
  let
    m = cpt result
    sm = cpt signed_message
    smlen = culen signed_message
    pk = cpt public_key
    rc = crypto_sign_open(m, nil, sm, smlen, pk)
  check_rc rc


# Sealed boxes
# https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html


proc crypto_box_seal(
  c: cptr;
  m: cptr,
  mlen: culonglong,
  pk: cptr,
): cint {.sodium_import.}

proc crypto_box_seal*(message: string, public_key: CryptoBoxPublicKey): string =
  ## Encrypt a message using the receiver public key
  assert public_key.len == crypto_box_PUBLICKEYBYTES()
  result = newString(message.len + crypto_box_SEALBYTES())
  let
    pk = cpt public_key
    msg = cpt message
    msg_len = culen message
    c = cpt result
    rc = crypto_box_seal(c, msg, msg_len, pk)
  check_rc rc


proc crypto_box_seal_open(
  m: cptr,
  c: cptr,
  clen: culonglong,
  pk: cptr,
  sk: cptr,
): cint {.sodium_import.}

proc crypto_box_seal_open*(ciphertext: string, public_key: CryptoBoxPublicKey,
    secret_key: CryptoBoxSecretKey): string =
  ## Decrypt a ciphertext using a public and secret key
  assert public_key.len == crypto_box_PUBLICKEYBYTES()
  assert secret_key.len == crypto_box_SECRETKEYBYTES()
  result = newString(ciphertext.len - crypto_box_SEALBYTES())
  let
    m = cpt result
    c = cpt ciphertext
    clen = culen ciphertext
    pk = cpt public_key
    sk = cpt secret_key
    rc = crypto_box_seal_open(m, c, clen, pk, sk)
  check_rc rc


# Generic hashing
# https://download.libsodium.org/doc/hashing/generic_hashing.html


proc crypto_generichash(
  h: cptr,
  hlen: csize_t,
  m: cptr,
  mlen: culonglong,
  key: cptr,
  keylen: csize_t,
): cint {.sodium_import.}

proc crypto_generichash*(data: string, hashlen: int = crypto_generichash_BYTES(
    ).int, key: string = ""): string =
  ## Generate a hash of "data" of len "hashlen" using an optional key
  ## hashlen defaults to crypto_generichash_BYTES
  if key != "":
    doAssert(crypto_generichash_KEYBYTES_MIN().int <= key.len)
    doAssert(key.len <= crypto_generichash_KEYBYTES_MAX().int)

  result = newString hashlen
  let
    h = cpt result
    hlen =
      if hashlen == -1: csize_t(crypto_generichash_BYTES())
      else: csize_t(hashlen)

    m = cpt data
    mlen = culen data
    k =
      if key == "": nil
      else: cpt key

    klen = cpsize key
    rc = crypto_generichash(h, hlen, m, mlen, k, klen)
  check_rc rc


type GenericHash* = tuple
  state: string
  out_len: int

proc crypto_generichash_init(
  state: cptr,
  key: cptr,
  keylen: csize_t,
  outlen: csize_t
): cint {.sodium_import.}

proc crypto_generichash_update(
  state: cptr,
  data: cptr,
  data_len: culonglong
): cint {.sodium_import.}

proc crypto_generichash_final(
  state: cptr,
  output: cptr,
  out_len: csize_t,
): cint {.sodium_import.}


proc new_generic_hash*(key: string, out_len: int = crypto_generichash_BYTES().int): GenericHash =
  ## Create a new multipart hash, returns a GenericHash.
  ## The GenericHash is to be updated with .update()
  ## Upon calling .finalize() on it it will return a hash value of length "out_len"
  if key != "":
    doAssert crypto_generichash_KEYBYTES_MIN().int <= key.len
    doAssert key.len <= crypto_generichash_KEYBYTES_MAX().int
  doAssert crypto_generichash_BYTES_MIN().int <= out_len
  doAssert out_len <= crypto_generichash_BYTES_MAX().int

  result = (newString crypto_generichash_statebytes(), out_len)
  let
    state = cpt result.state
    k =
      if key == "": nil
      else: cpt key
    klen = cpsize key
    olen = csize_t out_len
    rc = crypto_generichash_init(state, k, klen, olen)
  check_rc rc

proc update*(self: GenericHash, data: string) =
  ## Update the multipart hash with more data
  let
    s = cpt self.state
    d = cpt data
    d_len = culen data
    rc = crypto_generichash_update(s, d, d_len)
  check_rc rc

proc finalize*(self: GenericHash): string =
  ## Finish the multipart hash and return the hash value as a string
  result = newString self.out_len
  let
    s = cpt self.state
    h = cpt result
    h_len = csize_t self.out_len
    rc = crypto_generichash_final(s, h, h_len)
  check_rc rc
  assert h.len == self.out_len


# Short-input hashing
# https://download.libsodium.org/doc/hashing/short-input_hashing.html

type ShortHashKey = string

proc crypto_shorthash(
  o: cptr,
  data: cptr,
  data_len: culonglong,
  k: cptr,
): cint {.sodium_import.}


proc crypto_shorthash*(data: string, key: ShortHashKey): string =
  ## Hash optimized for short inputs
  doAssert key.len == crypto_shorthash_KEYBYTES()
  result = newString crypto_shorthash_BYTES()
  let
    o = cpt result
    d = cpt data
    d_len = culen data
    k = cpt key
    rc = crypto_shorthash(o, d, d_len, k)
  check_rc rc

proc generate_key_for_short_hash*(): ShortHashKey =
  return randombytes(crypto_shorthash_KEYBYTES())


# Password hashing
# https://download.libsodium.org/doc/password_hashing

type
  PasswordHashingAlgorithm* = enum
    ## Password hashing algorithm
    phaDefault    ## Currently recommended algorithm, can change from one version
                  ## of libsodium to another.
    phaArgon2i13  ## Version 1.3 of the Argon2i algorithm
    phaArgon2id13 ## Version 1.3 of the Argon2id algorithm, available since
                  ## libsodium 1.0.13

proc crypto_pwhash(
  `out`: cptr,
  outlen: culonglong,
  passwd: cstring,
  passwdlen: culonglong,
  salt: cptr,
  opslimit: culonglong,
  memlimit: csize_t,
  alg: cint
): cint {.sodium_import.}

proc crypto_pwhash_alg_default(): cint {.sodium_import.}
proc crypto_pwhash_alg_argon2i13(): cint {.sodium_import.}
proc crypto_pwhash_alg_argon2id13(): cint {.sodium_import.}
proc crypto_pwhash_strprefix*(): cstring {.sodium_import.}

proc toCAlg(alg: PasswordHashingAlgorithm): cint =
  case alg
  of phaDefault: crypto_pwhash_alg_default()
  of phaArgon2i13: crypto_pwhash_alg_argon2i13()
  of phaArgon2id13: crypto_pwhash_alg_argon2id13()

proc crypto_pwhash*(passwd: string, salt: openArray[byte], outlen: Natural,
                    alg = phaDefault,
                    opslimit = crypto_pwhash_opslimit_moderate(),
                    memlimit = crypto_pwhash_memlimit_moderate()
                   ): seq[byte] =
  ## Derive an ``outlen`` long key from a password ``passwd`` whose length is in
  ## between ``crypto_pwhash_passwd_min()`` and ``crypto_pwhash_passwd_max()``
  ## and a salt of fixed length of ``crypto_pwhash_saltbytes()``.
  ##
  ## ``outlen`` should be at least ``crypto_pwhash_bytes_min()`` and at most
  ## ``crypto_pwhash_bytes_max()``
  ##
  ## See also:
  ## * `crypto_pwhash_str proc <#crypto_pwhash_str,string>`_
  runnableExamples:
    import sodium_sizes
    const Password = "Correct Horse Battery Staple"

    var salt = cast[seq[byte]](randombytes crypto_pwhash_saltbytes().int)
    let key = crypto_pwhash(Password, salt, crypto_box_seedbytes())

  doAssert salt.len == crypto_pwhash_saltbytes().int
  doAssert passwd.len.csize_t >= crypto_pwhash_passwd_min() and
           passwd.len.csize_t <= crypto_pwhash_passwd_max()
  doAssert outlen.csize_t >= crypto_pwhash_bytes_min() and
           outlen.csize_t <= crypto_pwhash_bytes_max()

  newSeq[byte](result, outlen)
  let
    cout = cast[cptr](addr result[0]) # This is safe, since Nim's byte is
                                      # an uint8, just like char
    coutlen = outlen.culonglong
    cpasswd = passwd.cstring
    cpasswdlen = passwd.len.culonglong
    # Same as above, also, since this is a const param, we can be sure that
    # the array won't get modified, justifying the use of `unsafeAddr`
    csalt = cast[cptr](unsafeAddr salt[0])
    copslimit = opslimit.culonglong
    cmemlimit = memlimit.csize_t
    calg = alg.toCAlg
  check_rc crypto_pwhash(cout, coutlen, cpasswd, cpasswdlen, csalt, copslimit,
                         cmemlimit, calg)

proc crypto_pwhash_str_alg(
  `out`: cstring,
  passwd: cstring,
  passwdlen: culonglong,
  opslimit: culonglong,
  memlimit: csize_t,
  alg: cint
): cint {.sodium_import.}

proc crypto_pwhash_str*(passwd: string, alg = phaDefault,
                        opslimit = crypto_pwhash_opslimit_moderate(),
                        memlimit = crypto_pwhash_memlimit_moderate()
                       ): string =
  ## Returns an ASCII encoded string which includes:
  ## * the result of the chosen hash algorithm ``alg`` applied to the
  ##   password ``passwd`` (the default is a memory-hard, CPU-intensive hash
  ##   function). The password length must be in the range
  ##   between ``crypto_pwhash_passwd_min()`` and ``crypto_pwhash_passwd_max()``
  ## * the automatically generated salt used for the previous computation.
  ## * the other parameters required to verify the password.
  ##
  ## The returned string includes only ASCII characters and can be safely
  ## stored into SQL databases and other data stores.
  ##
  ## See also:
  ## * `crypto_pwhash proc <#crypto_pwhash,string,openArray[byte],Natural>`_
  ## * `crypto_pwhash_str_verify proc <#crypto_pwhash_str_verify,string,string>`_
  runnableExamples:
    const Password = "Correct Horse Battery Staple"
    let hashed_password = crypto_pwhash_str(Password)

    doAssert crypto_pwhash_str_verify(hashed_password, Password)

  doAssert passwd.len.csize_t >= crypto_pwhash_passwd_min() and
           passwd.len.csize_t <= crypto_pwhash_passwd_max()

  result = newString crypto_pwhash_strbytes()

  let
    cout = cstring result
    cpasswd = cstring passwd
    cpasswdlen = passwd.len.culonglong
    copslimit = opslimit.culonglong
    cmemlimit = memlimit.csize_t
    calg = alg.toCAlg()

  check_rc crypto_pwhash_str_alg(cout, cpasswd, cpasswdlen, copslimit, cmemlimit,
                                 calg)

  result.setLen cout.len

proc crypto_pwhash_str_verify(
  str, passwd: cstring,
  passwdlen: culonglong
): cint {.sodium_import.}

proc crypto_pwhash_str_verify*(str, passwd: string): bool {.inline.} =
  ## Verifies that str is a valid password verification string (as generated by
  ## ``crypto_pwhash_str()``) for ``passwd``
  ##
  ## See also:
  ## * `crypto_pwhash_str proc <#crypto_pwhash_str,string>`_
  result = crypto_pwhash_str_verify(cstring str, cstring passwd,
                                    passwd.len.culonglong) == 0

proc crypto_pwhash_str_needs_rehash(
  str: cstring,
  opslimit: culonglong,
  memlimit: csize_t
): cint {.sodium_import.}

proc crypto_pwhash_str_needs_rehash*(str: string,
                                     opslimit = crypto_pwhash_opslimit_moderate(),
                                     memlimit = crypto_pwhash_memlimit_moderate()
                                    ): int {.inline.} =
  ## Check if a password verification string ``str`` matches the parameters
  ## ``opslimit`` and ``memlimit``, and the current default algorithm.
  ##
  ## The functions returns:
  ## * `1` if the string appears to be correct, but doesn't match the given
  ##   parameters. In that situation, applications may want to compute
  ##   a new hash using the current parameters the next time the user logs in.
  ## * `0` if the parameters already match the given ones.
  ## * `-1` on error. If it happens, applications may want to compute
  ##   a correct hash the next time the user logs in.
  ##
  ## See also:
  ## * `crypto_pwhash_str proc <#crypto_pwhash_str,string>`_
  ## * `crypto_pwhash_str_verify proc <#crypto_pwhash_str_verify,string,string>`_
  int crypto_pwhash_str_needs_rehash(cstring str, culonglong opslimit,
                                     csize_t memlimit)

# Diffie-Hellman function
# https://download.libsodium.org/doc/advanced/scalar_multiplication.html


proc crypto_scalarmult_base(
  q: cptr,
  n: cptr,
): cint {.sodium_import.}

proc crypto_scalarmult_base*(secret_key: string): string =
  assert secret_key.len == crypto_scalarmult_SCALARBYTES()
  result = newString crypto_scalarmult_BYTES()
  let
    q = cpt result
    n = cpt secret_key
    rc = crypto_scalarmult_base(q, n)
  check_rc rc


proc crypto_scalarmult(
  q: cptr,
  n: cptr,
  p: cptr,
): cint {.sodium_import.}

proc crypto_scalarmult*(secret_key, public_key: string): string =
  ## Compute a shared secret given a secret key and another user's public key.
  ## The Sodium library recommends *not* using the shared secred directly, rather
  ## a hash of the shared secred concatenated with the public keys from both users
  assert secret_key.len == crypto_scalarmult_SCALARBYTES()
  assert public_key.len == crypto_scalarmult_BYTES()
  result = newString crypto_scalarmult_BYTES()
  let
    q = cpt result     # output
    n = cpt secret_key # secret key
    p = cpt public_key # public key
    rc = crypto_scalarmult(q, n, p)
  check_rc rc

# Secret-key single-message authentication using Poly1305
# https://download.libsodium.org/doc/advanced/poly1305.html

proc crypto_onetimeauth(
  o: cptr,
  msg: cptr,
  msg_len: culonglong,
  key: cptr
): cint {.sodium_import.}

proc crypto_onetimeauth*(message, key: string): string =
  ## One-time authentication using Poly1305
  ## Warning: Use unpredictable, secret, unique keys
  assert key.len == crypto_onetimeauth_KEYBYTES()
  result = newString crypto_onetimeauth_BYTES()
  let
    o = cpt result
    msg = cpt message
    msg_len = culen message
    k = cpt key
    rc = crypto_onetimeauth(o, msg, msg_len, k)
  check_rc rc


proc crypto_onetimeauth_verify(
  o: cptr,
  msg: cptr,
  msg_len: culonglong,
  key: cptr
): cint {.sodium_import.}

proc crypto_onetimeauth_verify*(tok, message, key: string): bool =
  ## Verify onetimeauth
  assert key.len == crypto_onetimeauth_KEYBYTES()
  assert tok.len == crypto_onetimeauth_BYTES()
  let
    o = cpt tok
    msg = cpt message
    msg_len = culen message
    k = cpt key
    rc = crypto_onetimeauth_verify(o, msg, msg_len, k)
  return rc == 0

# HMAC

proc crypto_auth_hmacsha256(
  o: cptr,
  i: cptr,
  inlen: culonglong,
  k: cptr
): cint {.sodium_import.}

proc crypto_auth_hmacsha256*(message, key: string): string =
  ## HMAC SHA256
  assert key.len == crypto_auth_hmacsha256_keybytes()
  result = newString crypto_auth_hmacsha256_bytes()
  let
    o = cpt result
    msg = cpt message
    msg_len = culen message
    k = cpt key
    rc = crypto_auth_hmacsha256(o, msg, msg_len, k)
  check_rc rc

proc crypto_auth_hmacsha256_verify(
  h: cptr,
  i: cptr,
  inlen: culonglong,
  k: cptr,
): cint {.sodium_import.}

proc crypto_auth_hmacsha256_verify*(mac, message, key: string): bool =
  ## HMAC SHA256 verification
  assert mac.len == crypto_auth_hmacsha256_bytes()
  assert key.len == crypto_auth_hmacsha256_keybytes()
  let
    tag = cpt mac
    msg = cpt message
    msg_len = culen message
    k = cpt key
    rc = crypto_auth_hmacsha256_verify(tag, msg, msg_len, k)

  return rc == 0

proc crypto_auth_hmacsha256_init(
  state: cptr,
  key: cptr,
  keylen: culonglong
): cint {.sodium_import.}

proc crypto_auth_hmacsha256_update(
  state: cptr,
  data: cptr,
  data_len: culonglong
): cint {.sodium_import.}

proc crypto_auth_hmacsha256_final(
  state: cptr,
  output: cptr,
): cint {.sodium_import.}

type HMACSHA256State* = tuple
  state: string

proc new_crypto_auth_hmacsha256*(key: string): HMACSHA256State =
  ## Create multipart SHA256 HMAC
  ## Create a new multipart hash, returns a HMACSHA256State
  ## The HMACSHA256State is to be updated with .update()
  ## Upon calling .finalize() on it it will return a hash value
  result.state = newString crypto_auth_hmacsha256_statebytes()
  let
    state = cpt result.state
    k =
      if key == "": nil
      else: cpt key
    klen = culen key
    rc = crypto_auth_hmacsha256_init(state, k, klen)
  check_rc rc

proc update*(self: HMACSHA256State, data: string) =
  ## Update the multipart hash with more data
  let
    s = cpt self.state
    d = cpt data
    d_len = culen data
    rc = crypto_auth_hmacsha256_update(s, d, d_len)
  check_rc rc

proc finalize*(self: HMACSHA256State): string =
  ## Finish the multipart hash and return the hash value as a string
  result = newString crypto_auth_hmacsha256_bytes()
  let
    s = cpt self.state
    h = cpt result
    rc = crypto_auth_hmacsha256_final(s, h)
  check_rc rc



# Stream ciphers

# Salsa20

proc crypto_stream_salsa20(
  c: cptr,
  clen: culonglong,
  n: cptr,
  k: cptr
): cint {.sodium_import.}

proc crypto_stream_salsa20*(nonce, key: string, length: int): string =
  ## Salsa20 stream cypher.
  ## `nonce` requires length of crypto_stream_salsa20_NONCEBYTES (64 bits)
  ## `key` requires crypto_stream_salsa20_KEYBYTES (256 bits)
  ## Returns `length` bytes.
  doAssert nonce.len == crypto_stream_salsa20_NONCEBYTES()
  doAssert key.len == crypto_stream_salsa20_KEYBYTES()
  result = newString length
  let
    c = cpt result
    clen = culen result
    n = cpt nonce
    k = cpt key
    rc = crypto_stream_salsa20(c, clen, n, k)
  check_rc rc


proc crypto_stream_salsa20_xor(
  c: cptr,
  m: cptr,
  mlen: culonglong,
  n: cptr,
  k: cptr
): cint {.sodium_import.}

proc crypto_stream_salsa20_xor*(nonce, key, msg: string): string =
  ## encrypts `msg`.
  ## `nonce` requires length of crypto_stream_salsa20_NONCEBYTES
  ## `key` requires crypto_stream_salsa20_KEYBYTES
  result = newString msg.len
  let
    c = cpt result
    m = cpt msg
    mlen = culen msg
    n = cpt nonce
    k = cpt key
    rc = crypto_stream_salsa20_xor(c, m, mlen, n, k)
  check_rc rc


proc crypto_stream_salsa20_xor_ic(
  c: cptr,
  m: cptr,
  mlen: culonglong,
  n: cptr,
  ic: uint64,
  k: cptr
): cint {.sodium_import.}

proc crypto_stream_salsa20_xor_ic*(nonce, key, msg: string, ic: uint): string =
  ## encrypts `msg`.
  ## `nonce` requires length of crypto_stream_salsa20_NONCEBYTES
  ## `key` requires crypto_stream_salsa20_KEYBYTES
  ## `ic` is the initial value for the block counter.
  result = newString msg.len
  let
    c = cpt result
    m = cpt msg
    mlen = culen msg
    n = cpt nonce
    k = cpt key
    rc = crypto_stream_salsa20_xor_ic(c, m, mlen, n, ic.cuint, k)
  check_rc rc


proc crypto_stream_salsa20_keygen(
  k: cptr,
) {.sodium_import.}

proc crypto_stream_salsa20_keygen*(): string =
  ## Returns `crypto_stream_salsa20_KEYBYTES` random bytes.
  result = newString crypto_stream_salsa20_KEYBYTES()
  let o = cpt result
  crypto_stream_salsa20_keygen(o)


# XSalsa20

proc crypto_stream(
  c: cptr,
  clen: culonglong,
  n: cptr,
  k: cptr
): cint {.sodium_import.}

proc crypto_stream*(nonce, key: string, length: int): string =
  ## XSalsa20 stream cypher.
  ## `nonce` requires length of crypto_stream_xsalsa20_NONCEBYTES (192 bits)
  ## `key` requires crypto_stream_xsalsa20_KEYBYTES (256 bits)
  ## Returns `length` bytes.
  doAssert nonce.len == crypto_stream_xsalsa20_NONCEBYTES()
  doAssert key.len == crypto_stream_xsalsa20_KEYBYTES()
  result = newString length
  let
    c = cpt result
    clen = culen result
    n = cpt nonce
    k = cpt key
    rc = crypto_stream(c, clen, n, k)
  check_rc rc


proc crypto_stream_xor(
  c: cptr,
  m: cptr,
  mlen: culonglong,
  n: cptr,
  k: cptr
): cint {.sodium_import.}

proc crypto_stream_xor*(nonce, key, msg: string): string =
  ## encrypts `msg` using XSalsa20.
  ## `nonce` requires length of crypto_stream_xsalsa20_NONCEBYTES
  ## `key` requires crypto_stream_xsalsa20_KEYBYTES
  result = newString msg.len
  let
    c = cpt result
    m = cpt msg
    mlen = culen msg
    n = cpt nonce
    k = cpt key
    rc = crypto_stream_xor(c, m, mlen, n, k)
  check_rc rc


proc crypto_stream_keygen(
  k: cptr,
) {.sodium_import.}

proc crypto_stream_keygen*(): string =
  ## Returns `crypto_stream_xsalsa20_KEYBYTES` random bytes.
  ## To be used with `crypto_stream` or `crypto_stream_xor`
  result = newString crypto_stream_salsa20_KEYBYTES()
  let o = cpt result
  crypto_stream_keygen(o)

# Key exchange
# https://download.libsodium.org/doc/key_exchange.html

type
  CryptoKxPublicKey = string
  CryptoKxSecretKey = string
  CryptoKxRxKey = string
  CryptoKxTxKey = string

#TODO crypto_kx_seed_keypair

proc crypto_kx_keypair(
  pk: cptr,
  sk: cptr
): cint {.sodium_import.}

proc crypto_kx_keypair*(): (CryptoKxPublicKey, CryptoKxSecretKey) =
  result[0] = newString crypto_kx_PUBLICKEYBYTES()
  result[1] = newString crypto_kx_SECRETKEYBYTES()
  let
    pk = cpt result[0]
    sk = cpt result[1]
  let rc = crypto_kx_keypair(pk, sk)
  check_rc rc


proc crypto_kx_client_session_keys(
  rx: cptr,
  tx: cptr,
  client_pk: cptr,
  client_sk: cptr,
  server_pk: cptr,
): cint {.sodium_import.}

proc crypto_kx_client_session_keys*(client_pk, client_sk, server_pk: string): (
    CryptoKxRxKey, CryptoKxTxKey) =
  ## Generate key exchange client keys
  result[0] = newString crypto_kx_SESSIONKEYBYTES()
  result[1] = newString crypto_kx_SESSIONKEYBYTES()
  let
    rx = cpt result[0]
    tx = cpt result[1]
    cpk = cpt client_pk
    csk = cpt client_sk
    spk = cpt server_pk
    rc = crypto_kx_client_session_keys(rx, tx, cpk, csk, spk)
  check_rc rc


proc crypto_kx_server_session_keys(
  rx: cptr,
  tx: cptr,
  server_pk: cptr,
  server_sk: cptr,
  client_pk: cptr,
): cint {.sodium_import.}

proc crypto_kx_server_session_keys*(server_pk, server_sk, client_pk: string): (
    CryptoKxRxKey, CryptoKxTxKey) =
  ## Generate key exchange server keys
  result[0] = newString crypto_kx_SESSIONKEYBYTES()
  result[1] = newString crypto_kx_SESSIONKEYBYTES()
  let
    rx = cpt result[0]
    tx = cpt result[1]
    spk = cpt server_pk
    ssk = cpt server_sk
    cpk = cpt client_pk
    rc = crypto_kx_server_session_keys(rx, tx, spk, ssk, cpk)
  check_rc rc


# Secret stream
# https://download.libsodium.org/doc/secret-key_cryptography/secretstream

type
  SecretStreamXChaCha20Poly1305Key* = string
  SecretStreamXChaCha20Poly1305Header* = string
  SecretStreamXChaCha20Poly1305PushState * = tuple
    state: string
  SecretStreamXChaCha20Poly1305PullState * = tuple
    state: string

proc crypto_secretstream_xchacha20poly1305_keygen(
  key: cptr,
) {.sodium_import.}

proc crypto_secretstream_xchacha20poly1305_keygen*(): SecretStreamXChaCha20Poly1305Key =
  # Generate a key for secretstream functions
  result = newString crypto_secretstream_xchacha20poly1305_KEYBYTES()
  let
    o = cpt result
  crypto_secretstream_xchacha20poly1305_keygen(o)

proc crypto_secretstream_xchacha20poly1305_tag_message*(): char {.sodium_import.}
proc crypto_secretstream_xchacha20poly1305_tag_push*(): char {.sodium_import.}
proc crypto_secretstream_xchacha20poly1305_tag_rekey*(): char {.sodium_import.}
proc crypto_secretstream_xchacha20poly1305_tag_final*(): char {.sodium_import.}


proc crypto_secretstream_xchacha20poly1305_init_push(
  state: cptr,
  header: cptr,
  key: cptr,
): cint {.sodium_import.}

proc crypto_secretstream_xchacha20poly1305_init_push*(
  key: SecretStreamXChaCha20Poly1305Key): (
    SecretStreamXChaCha20Poly1305PushState,
    SecretStreamXChaCha20Poly1305Header) =
  ## Initialize encryption for a secret stream
  let
    state = (state: newString crypto_secretstream_xchacha20poly1305_statebytes(), )
    header = newString crypto_secretstream_xchacha20poly1305_headerbytes()
    c_state = cpt state.state
    c_header = cpt header
    k =
      if key == "": nil
      else: cpt key
    rc = crypto_secretstream_xchacha20poly1305_init_push(c_state, c_header, k)
  result = (state, header)
  check_rc rc

proc crypto_secretstream_xchacha20poly1305_init_pull(
  state: cptr,
  header: cptr,
  key: cptr,
): cint {.sodium_import.}

proc crypto_secretstream_xchacha20poly1305_init_pull*(
  header: SecretStreamXChaCha20Poly1305Header,
    key: SecretStreamXChaCha20Poly1305Key): SecretStreamXChaCha20Poly1305PullState =
  ## Initialize decryption for a secret stream
  let
    state = (state: newString crypto_secretstream_xchacha20poly1305_statebytes(), )
    c_state = cpt state.state
    c_header = cpt header
    k =
      if key == "": nil
      else: cpt key
    rc = crypto_secretstream_xchacha20poly1305_init_pull(c_state, c_header, k)
  result = state
  check_rc rc

proc crypto_secretstream_xchacha20poly1305_push(
  state: cptr,
  outs: cptr,
  outlen_p: ptr culonglong,
  m: cptr,
  mlen: culonglong,
  ad: cptr,
  adlen: culonglong,
  tag: char,
): cint {.sodium_import.}

proc push*(state: SecretStreamXChaCha20Poly1305PushState, msg, ad: string,
    tag: char): string =
  ## Perform crypto_secretstream_xchacha20poly1305_push
  result = newString(msg.len + crypto_secretstream_xchacha20poly1305_ABYTES())
  let
    c_state = cpt state.state
    cipher = cpt result
    m = cpt msg
    mlen = culen msg
    c_ad = cpt ad
    c_adlen = culen ad
    rc = crypto_secretstream_xchacha20poly1305_push(
      c_state,
      cipher,
      nil,
      m,
      mlen,
      c_ad,
      c_adlen,
      tag,
    )
  check_rc rc


proc crypto_secretstream_xchacha20poly1305_pull(
  state: cptr,
  m: cptr,
  mlen_p: ptr culonglong,
  tag_p: cptr,
  ins: cptr,
  inlen: culonglong,
  ad: cptr,
  adlen: culonglong,
): cint {.sodium_import.}

proc pull*(state: SecretStreamXChaCha20Poly1305PullState, cipher, ad: string): (
    string, char) =
  ## Perform crypto_secretstream_xchacha20poly1305_pull
  result[0] = newString(cipher.len - crypto_secretstream_xchacha20poly1305_ABYTES())
  let
    c_state = cpt state.state
    m = cpt result[0]
    c_in = cpt cipher
    c_inlen = culen cipher
    c_ad = cpt ad
    c_adlen = culen ad
    rc = crypto_secretstream_xchacha20poly1305_pull(
      c_state,
      m,
      nil,
      result[1].unsafeAddr,
      c_in,
      c_inlen,
      c_ad,
      c_adlen,
    )
  check_rc rc


# Padding
# https://download.libsodium.org/doc/padding

proc sodium_pad(
  padded_buflen_p: ptr csize_t,
  buf: cptr,
  unpadded_buflen: csize_t,
  blocksize: csize_t,
  max_buflen: csize_t,
): cint {.sodium_import.}

proc sodium_pad*(msg: string, blocksize: int): string =
  let maxsize = ((msg.len div blocksize) + 1) * blocksize
  result = newString maxsize
  for i, c in msg:
    result[i] = c
  var
    buflen: csize_t
  let
    padded_buflen_p = buflen.unsafeAddr
    buf = cpt result
    unpadded_buflen = msg.len.csize_t
    blocksize = blocksize.csize_t
    max_buflen = maxsize.csize_t
  check_rc sodium_pad(
    padded_buflen_p,
    buf,
    unpadded_buflen,
    blocksize,
    max_buflen,
  )
  result.setLen(buflen)

proc sodium_unpad(
  unpadded_buflen_p: ptr csize_t,
  buf: cptr,
  padded_buflen: csize_t,
  blocksize: csize_t,
): cint {.sodium_import.}

proc sodium_unpad*(padded: string, blocksize: int): string =
  result = $padded
  var
    buflen: csize_t
  let
    unpadded_buflen_p = buflen.unsafeAddr
    buf = cpt result
    padded_buflen = padded.len.csize_t
    blocksize = blocksize.csize_t
  check_rc sodium_unpad(
    unpadded_buflen_p,
    buf,
    padded_buflen,
    blocksize,
  )
  result.setLen(buflen)
