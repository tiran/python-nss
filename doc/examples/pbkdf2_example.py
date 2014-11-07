#!/usr/bin/python

import argparse
import sys

import nss.nss as nss
import nss.error as nss_error

#-------------------------------------------------------------------------------

options = None

#-------------------------------------------------------------------------------

def fmt_info(label, item, level=0, hex_data=False):
    fmt_tuples = nss.make_line_fmt_tuples(level, label+':')
    if hex_data:
        fmt_tuples.extend(nss.make_line_fmt_tuples(level+1,
                                                   nss.data_to_hex(item, 16)))
    elif isinstance(item, basestring):
        fmt_tuples.extend(nss.make_line_fmt_tuples(level+1, str(item)))
    else:
        fmt_tuples.extend(item.format_lines(level=level+1))
    return nss.indented_format(fmt_tuples)


def generate_key():

    # The AlgorithmID bundles up all the parameters used to
    # generate a symmetric key
    #
    # Note, the defaults for create_pbev2_algorithm_id() are
    # usually correct for most uses, thus one can call
    # create_pbev2_algorithm_id() with no parameters.
    # The parameters are only specified here because this is
    # an example script people can play with.
    alg_id = nss.create_pbev2_algorithm_id(options.pbe_alg,
                                           options.cipher_alg,
                                           options.prf_alg,
                                           options.key_length,
                                           options.iterations,
                                           options.salt)

    if not options.quiet:
        print fmt_info("create_pbev2_algorithm_id returned()", alg_id)
        print


    # Pick a PK11 Slot to operate in, we'll use the internal slot
    slot = nss.get_internal_slot()

    # Generate the symmetric key
    sym_key = slot.pbe_key_gen(alg_id, options.password)

    if not options.quiet:
        print fmt_info("Using password", options.password)
        print
        print fmt_info("pbe_key_gen() returned sym_key", sym_key)
        print

    return alg_id, sym_key

def get_encryption_contexts(alg_id, sym_key):

    # In order for NSS to encrypt and decrypt data it needs an
    # encryption context to perform the operation in. The cipher used
    # for the encryption context is specified with a PK11 mechanism.
    # The cipher likely also needs additional parameters (i.e. an
    # Initialization Vector (IV) and possibly other values.
    # The get_pbe_crypto_mechanism() call computes the mechanism
    # and parameters for the PBE symmetric key we're using.
    mechanism, params = alg_id.get_pbe_crypto_mechanism(sym_key)

    if not options.quiet:
        print fmt_info("get_pbe_crypto_mechanism returned mechanism:",
                       nss.key_mechanism_type_name(mechanism))
        print

    # Now we have enough information to create a context encrypting
    # and decrypting the data.

    encrypt_ctx = nss.create_context_by_sym_key(mechanism, nss.CKA_ENCRYPT,
                                                sym_key, params)
    decrypt_ctx = nss.create_context_by_sym_key(mechanism, nss.CKA_DECRYPT,
                                                sym_key, params)

    return encrypt_ctx, decrypt_ctx

def do_pbkdf2():

    # Generate a symmetric key
    alg_id, sym_key = generate_key()

    # Get encryption contexts to encrypt and decrypt given the sym_key
    encrypt_ctx, decrypt_ctx = get_encryption_contexts(alg_id, sym_key)

    # First encrypt the plain text input, then decrypt again

    print fmt_info("Plain Text", options.plain_text)
    print

    # Encode the plain text by feeding it to cipher_op getting cipher text back.
    # Append the final bit of cipher text by calling digest_final
    cipher_text = encrypt_ctx.cipher_op(options.plain_text)
    cipher_text += encrypt_ctx.digest_final()

    print fmt_info("Cipher Text", cipher_text, hex_data=True)
    print

    # Decode the cipher text by feeding it to cipher_op getting plain text back.
    # Append the final bit of plain text by calling digest_final
    decoded_text = decrypt_ctx.cipher_op(cipher_text)
    decoded_text += decrypt_ctx.digest_final()

    print fmt_info("Decoded Text", decoded_text)
    print

#-------------------------------------------------------------------------------
def main():
    global options

    parser = argparse.ArgumentParser(description='Password Based Encryption Example')

    parser.add_argument('-q', '--quiet', action='store_true',
                        help='stiffle chatty output')

    # === NSS Database Group ===
    group = parser.add_argument_group('PBKDF2',
                                      'Specify the PBKDF2 parameters')

    group.add_argument('--pbe-alg',
                       help='password based encryption algorithm')
    group.add_argument('--cipher-alg',
                       help='cipher algorithm')
    group.add_argument('--prf-alg',
                       help='pseudo-random function algorithm')
    group.add_argument('-l', '--key-length',
                       help='number of octets in derived key')
    group.add_argument('-s', '--salt',
                       help='salt as a string, if none then use random data')


    group = parser.add_argument_group('Encryption',
                                      'Specify the encryption parameters')

    group.add_argument('-p', '--password',
                       help='PBE password')

    group.add_argument('-t', '--plain-text',
                       help='string to encrypt')

    parser.set_defaults(pbe_alg = 'SEC_OID_PKCS5_PBKDF2',
                        cipher_alg = 'SEC_OID_AES_256_CBC',
                        prf_alg = 'SEC_OID_HMAC_SHA1',
                        iterations = 100,
                        key_length = 0,
                        salt = None,
                        password = 'password',
                        plain_text = 'Black holes are where God divided by zero - Steven Wright',
                        )

    options = parser.parse_args()

    # Initialize NSS.
    nss.nss_init_nodb()

    do_pbkdf2()

#-------------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())
