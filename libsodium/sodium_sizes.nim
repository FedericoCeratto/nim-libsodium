#
# Libsodium18 wrapper for Nim
#
# 2016 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3, see LICENSE file
#
# Functions returning sizes of various elements

when defined(windows):
  const libsodium_fn* = "libsodium.dll"
elif defined(macosx):
  const libsodium_fn* = "libsodium.dylib"
else:
  const libsodium_fn* = "libsodium.so.18"

{.pragma: sodium_import, importc, dynlib: libsodium_fn.}

proc crypto_generichash_statebytes*(): cint {.sodium_import.}

const
  #[
  grep -rh '#define.*BYTES' sodium > defines.h

  grep '\\$' defines.h
  # hunt down and fix a few multiline defines by hand

  c2nim defines.h
  # reorder a few defines by hand
  ]#

  crypto_hash_sha512_BYTES* = 64
  crypto_sign_ed25519_BYTES* = 64
  crypto_sign_ed25519_SEEDBYTES* = 32
  crypto_sign_ed25519_PUBLICKEYBYTES* = 32
  crypto_sign_ed25519_SECRETKEYBYTES* = (32 + 32)
  crypto_hash_BYTES* = crypto_hash_sha512_BYTES
  crypto_shorthash_siphash24_BYTES* = 8
  crypto_shorthash_siphash24_KEYBYTES* = 16
  crypto_stream_salsa20_KEYBYTES* = 32
  crypto_stream_salsa20_NONCEBYTES* = 8
  crypto_verify_32_BYTES* = 32
  crypto_core_hsalsa20_OUTPUTBYTES* = 32
  crypto_core_hsalsa20_INPUTBYTES* = 16
  crypto_core_hsalsa20_KEYBYTES* = 32
  crypto_core_hsalsa20_CONSTBYTES* = 16
  crypto_scalarmult_curve25519_BYTES* = 32
  crypto_scalarmult_curve25519_SCALARBYTES* = 32
  crypto_sign_edwards25519sha512batch_BYTES* = 64
  crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES* = 32
  crypto_sign_edwards25519sha512batch_SECRETKEYBYTES* = (32 + 32)
  crypto_auth_hmacsha256_BYTES* = 32
  crypto_auth_hmacsha256_KEYBYTES* = 32
  crypto_secretbox_xsalsa20poly1305_KEYBYTES* = 32
  crypto_secretbox_xsalsa20poly1305_NONCEBYTES* = 24
  crypto_secretbox_xsalsa20poly1305_MACBYTES* = 16
  crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES* = 16
  crypto_secretbox_xsalsa20poly1305_ZEROBYTES* = (crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES +
      crypto_secretbox_xsalsa20poly1305_MACBYTES)
  crypto_auth_hmacsha512256_BYTES* = 32
  crypto_auth_hmacsha512256_KEYBYTES* = 32
  crypto_box_curve25519xsalsa20poly1305_SEEDBYTES* = 32
  crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES* = 32
  crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES* = 32
  crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES* = 32
  crypto_box_curve25519xsalsa20poly1305_NONCEBYTES* = 24
  crypto_box_curve25519xsalsa20poly1305_MACBYTES* = 16
  crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES* = 16
  crypto_box_curve25519xsalsa20poly1305_ZEROBYTES* = (crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES +
      crypto_box_curve25519xsalsa20poly1305_MACBYTES)
  crypto_aead_chacha20poly1305_ietf_KEYBYTES* = 32
  crypto_aead_chacha20poly1305_ietf_NSECBYTES* = 0
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES* = 12
  crypto_aead_chacha20poly1305_ietf_ABYTES* = 16
  crypto_aead_chacha20poly1305_KEYBYTES* = 32
  crypto_aead_chacha20poly1305_NSECBYTES* = 0
  crypto_aead_chacha20poly1305_NPUBBYTES* = 8
  crypto_aead_chacha20poly1305_ABYTES* = 16
  crypto_auth_BYTES* = crypto_auth_hmacsha512256_BYTES
  crypto_auth_KEYBYTES* = crypto_auth_hmacsha512256_KEYBYTES
  crypto_box_curve25519xchacha20poly1305_SEEDBYTES* = 32
  crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES* = 32
  crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES* = 32
  crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES* = 32
  crypto_box_curve25519xchacha20poly1305_NONCEBYTES* = 24
  crypto_box_curve25519xchacha20poly1305_MACBYTES* = 16
  crypto_box_curve25519xchacha20poly1305_BOXZEROBYTES* = 16
  crypto_box_curve25519xchacha20poly1305_ZEROBYTES* = (crypto_box_curve25519xchacha20poly1305_BOXZEROBYTES +
      crypto_box_curve25519xchacha20poly1305_MACBYTES)
  crypto_stream_xsalsa20_KEYBYTES* = 32
  crypto_stream_xsalsa20_NONCEBYTES* = 24
  crypto_stream_KEYBYTES* = crypto_stream_xsalsa20_KEYBYTES
  crypto_stream_NONCEBYTES* = crypto_stream_xsalsa20_NONCEBYTES
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES* = 32
  crypto_aead_xchacha20poly1305_ietf_NSECBYTES* = 0
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES* = 24
  crypto_aead_xchacha20poly1305_ietf_ABYTES* = 16
  crypto_onetimeauth_poly1305_BYTES* = 16
  crypto_onetimeauth_poly1305_KEYBYTES* = 32
  crypto_onetimeauth_BYTES* = crypto_onetimeauth_poly1305_BYTES
  crypto_onetimeauth_KEYBYTES* = crypto_onetimeauth_poly1305_KEYBYTES
  crypto_hash_sha256_BYTES* = 32
  crypto_pwhash_scryptsalsa208sha256_SALTBYTES* = 32
  crypto_pwhash_scryptsalsa208sha256_STRBYTES* = 102
  crypto_sign_BYTES* = crypto_sign_ed25519_BYTES
  crypto_sign_SEEDBYTES* = crypto_sign_ed25519_SEEDBYTES
  crypto_sign_PUBLICKEYBYTES* = crypto_sign_ed25519_PUBLICKEYBYTES
  crypto_sign_SECRETKEYBYTES* = crypto_sign_ed25519_SECRETKEYBYTES
  crypto_aead_aes256gcm_KEYBYTES* = 32
  crypto_aead_aes256gcm_NSECBYTES* = 0
  crypto_aead_aes256gcm_NPUBBYTES* = 12
  crypto_aead_aes256gcm_ABYTES* = 16
  crypto_shorthash_BYTES* = crypto_shorthash_siphash24_BYTES
  crypto_shorthash_KEYBYTES* = crypto_shorthash_siphash24_KEYBYTES
  crypto_auth_hmacsha512_BYTES* = 64
  crypto_auth_hmacsha512_KEYBYTES* = 32
  crypto_stream_salsa208_KEYBYTES* = 32
  crypto_stream_salsa208_NONCEBYTES* = 8
  crypto_stream_aes128ctr_KEYBYTES* = 16
  crypto_stream_aes128ctr_NONCEBYTES* = 16
  crypto_stream_aes128ctr_BEFORENMBYTES* = 1408
  crypto_core_salsa2012_OUTPUTBYTES* = 64
  crypto_core_salsa2012_INPUTBYTES* = 16
  crypto_core_salsa2012_KEYBYTES* = 32
  crypto_core_salsa2012_CONSTBYTES* = 16
  crypto_stream_chacha20_KEYBYTES* = 32
  crypto_stream_chacha20_NONCEBYTES* = 8
  crypto_stream_chacha20_IETF_NONCEBYTES* = 12
  crypto_generichash_blake2b_BYTES_MIN* = 16
  crypto_generichash_blake2b_BYTES_MAX* = 64
  crypto_generichash_blake2b_BYTES* = 32
  crypto_generichash_blake2b_KEYBYTES_MIN* = 16
  crypto_generichash_blake2b_KEYBYTES_MAX* = 64
  crypto_generichash_blake2b_KEYBYTES* = 32
  crypto_generichash_blake2b_SALTBYTES* = 16
  crypto_generichash_blake2b_PERSONALBYTES* = 16
  crypto_generichash_BYTES_MIN* = crypto_generichash_blake2b_BYTES_MIN
  crypto_generichash_BYTES_MAX* = crypto_generichash_blake2b_BYTES_MAX
  crypto_generichash_BYTES* = crypto_generichash_blake2b_BYTES
  crypto_generichash_KEYBYTES_MIN* = crypto_generichash_blake2b_KEYBYTES_MIN
  crypto_generichash_KEYBYTES_MAX* = crypto_generichash_blake2b_KEYBYTES_MAX
  crypto_generichash_KEYBYTES* = crypto_generichash_blake2b_KEYBYTES
  crypto_pwhash_argon2i_SALTBYTES* = 16
  crypto_pwhash_argon2i_STRBYTES* = 128
  crypto_box_SEEDBYTES* = crypto_box_curve25519xsalsa20poly1305_SEEDBYTES
  crypto_box_PUBLICKEYBYTES* = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
  crypto_box_SECRETKEYBYTES* = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
  crypto_box_NONCEBYTES* = crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
  crypto_box_MACBYTES* = crypto_box_curve25519xsalsa20poly1305_MACBYTES
  crypto_box_BEFORENMBYTES* = crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES
  crypto_box_SEALBYTES* = (crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES)
  crypto_box_ZEROBYTES* = crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
  crypto_box_BOXZEROBYTES* = crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
  crypto_pwhash_SALTBYTES* = crypto_pwhash_argon2i_SALTBYTES
  crypto_pwhash_STRBYTES* = crypto_pwhash_argon2i_STRBYTES
  crypto_stream_xchacha20_KEYBYTES* = 32
  crypto_stream_xchacha20_NONCEBYTES* = 24
  crypto_verify_16_BYTES* = 16
  crypto_verify_64_BYTES* = 64
  crypto_secretbox_xchacha20poly1305_KEYBYTES* = 32
  crypto_secretbox_xchacha20poly1305_NONCEBYTES* = 24
  crypto_secretbox_xchacha20poly1305_MACBYTES* = 16
  crypto_secretbox_xchacha20poly1305_BOXZEROBYTES* = 16
  crypto_secretbox_xchacha20poly1305_ZEROBYTES* = (crypto_secretbox_xchacha20poly1305_BOXZEROBYTES +
      crypto_secretbox_xchacha20poly1305_MACBYTES)
  crypto_secretbox_KEYBYTES* = crypto_secretbox_xsalsa20poly1305_KEYBYTES
  crypto_secretbox_NONCEBYTES* = crypto_secretbox_xsalsa20poly1305_NONCEBYTES
  crypto_secretbox_MACBYTES* = crypto_secretbox_xsalsa20poly1305_MACBYTES
  crypto_secretbox_ZEROBYTES* = crypto_secretbox_xsalsa20poly1305_ZEROBYTES
  crypto_secretbox_BOXZEROBYTES* = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES
  crypto_core_salsa208_OUTPUTBYTES* = 64
  crypto_core_salsa208_INPUTBYTES* = 16
  crypto_core_salsa208_KEYBYTES* = 32
  crypto_core_salsa208_CONSTBYTES* = 16
  crypto_core_hchacha20_OUTPUTBYTES* = 32
  crypto_core_hchacha20_INPUTBYTES* = 16
  crypto_core_hchacha20_KEYBYTES* = 32
  crypto_core_hchacha20_CONSTBYTES* = 16
  crypto_scalarmult_BYTES* = crypto_scalarmult_curve25519_BYTES
  crypto_scalarmult_SCALARBYTES* = crypto_scalarmult_curve25519_SCALARBYTES
  crypto_stream_salsa2012_KEYBYTES* = 32
  crypto_stream_salsa2012_NONCEBYTES* = 8
  crypto_core_salsa20_OUTPUTBYTES* = 64
  crypto_core_salsa20_INPUTBYTES* = 16
  crypto_core_salsa20_KEYBYTES* = 32
  crypto_core_salsa20_CONSTBYTES* = 16
