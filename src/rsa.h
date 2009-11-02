#ifndef _RSA_H
#define _RSA_H

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

#define ERR_RSA_KEYGEN_FAILED           0x0300
#define ERR_RSA_PUBLIC_FAILED           0x0320
#define ERR_RSA_PRIVATE_FAILED          0x0340
#define ERR_RSA_KEY_CHECK_FAILED        0x0360
#define ERR_RSA_ENCRYPT_FAILED          0x0380
#define ERR_RSA_DECRYPT_FAILED          0x03A0
#define ERR_RSA_SIGN_FAILED             0x03C0
#define ERR_RSA_VERIFY_FAILED           0x03E0

/*
 * PKCS#1 stuff
 */

#define RSA_MD2             2
#define RSA_MD4             3
#define RSA_MD5             4
#define RSA_SHA1            5

#define RSA_SIGN            0x01
#define RSA_CRYPT           0x02

/*
 * DigestInfo ::= SEQUENCE {
 *   digestAlgorithm DigestAlgorithmIdentifier,
 *   digest Digest }
 *
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * Digest ::= OCTET STRING
 */
#define ASN1_HASH_MDX                       \
    "\x30\x20\x30\x0C\x06\x08\x2A\x86\x48"  \
    "\x86\xF7\x0D\x02\x00\x05\x00\x04\x10"

#define ASN1_HASH_SHA1                      \
    "\x30\x21\x30\x09\x06\x05\x2B\x0E\x03"  \
    "\x02\x1A\x05\x00\x04\x14"

#include "mpi.h"

typedef struct
{
    uint ver;   /* should be 0      */
    uint len;   /* size(N) in chars */
    mpi N;      /* public modulus   */
    mpi E;      /* public exponent  */
    mpi D;      /* private exponent */
    mpi P;      /* 1st prime factor */
    mpi Q;      /* 2nd prime factor */
    mpi DP;     /* D mod (P - 1)    */
    mpi DQ;     /* D mod (Q - 1)    */
    mpi QP;     /* inverse of Q % P */
}
rsa_context;

/*
 * Generate a RSA keypair of nbits in size according
 * to the specified public exponent.
 *
 * Function "rng_func" takes one argument (rng_state)
 * and should return a random unsigned long.
 *
 * Returns 0 if successful, or ERR_RSA_KEYGEN_FAILED.
 */
int rsa_gen_key( rsa_context *ctx, uint nbits, uint exponent,
                 ulong (*rng_func)(void *), void *rng_state );

/*
 * Perform an RSA public key operation. This function
 * does not take care of message padding: both ilen and
 * olen must be equal to the modulus size (ctx->len).
 *
 * Returns 0 if successful, or ERR_RSA_PUBLIC_FAILED.
 */
int rsa_public( rsa_context *ctx, uchar *input,  uint ilen,
                                  uchar *output, uint olen );

/*
 * Perform an RSA private key operation. This function
 * does not take care of message padding: both ilen an
 * olen must be equal to the modulus size (ctx->len).
 *
 * Returns 0 if successful, or ERR_RSA_PRIVATE_FAILED.
 */
int rsa_private( rsa_context *ctx, uchar *input,  uint ilen,
                                   uchar *output, uint olen );

/*
 * Returns 0 if the public key is valid,
 * or ERR_RSA_KEY_CHECK_FAILED.
 */
int rsa_check_pubkey( rsa_context *ctx );

/*
 * Returns 0 if the private key is valid,
 * or ERR_RSA_KEY_CHECK_FAILED.
 */
int rsa_check_privkey( rsa_context *ctx );

/*
 * Add the PKCS1 v1.5 padding and perform a public RSA.
 *
 *      ctx     points to an RSA public key
 *      input   buffer holding the data to be encrypted
 *      ilen    length of the plaintext; cannot be longer
 *              than the modulus, minus 3+8 for padding
 *      output  buffer that will hold the ciphertext
 *      olen    must be the same as the modulus size
 *              (for example, 128 if RSA-1024 is used)
 *
 * Returns 0 if successful, or ERR_RSA_ENCRYPT_FAILED
 */
int rsa_pkcs1_encrypt( rsa_context *ctx,
                       uchar *input,  uint ilen,
                       uchar *output, uint olen );

/*
 * Perform a private RSA and remove the PKCS1 v1.5 padding.
 *
 *      ctx     points to an RSA private key
 *      input   buffer holding the encrypted data
 *      ilen    must be the same as the modulus size
 *      output  buffer that will hold the plaintext
 *      olen    size of output buffer, will be updated
 *              to contain the length of the plaintext
 *
 * Returns 0 if successful, or ERR_RSA_DECRYPT_FAILED
 */
int rsa_pkcs1_decrypt( rsa_context *ctx,
                       uchar *input,  uint  ilen,
                       uchar *output, uint *olen );

/*
 * Hash a message and perform a private RSA.
 *
 *      ctx     points to an RSA private key
 *      alg     must be set to RSA_MD2/4/5 or RSA_SHA1
 *      buf     buffer holding the data to be hashed
 *      buflen  length of the data
 *      sig     buffer that will hold the ciphertext
 *      siglen  must be the same as the modulus size
 *              (for example, 128 if RSA-1024 is used)
 *
 * Returns 0 if successful, or ERR_RSA_SIGN_FAILED
 */
int rsa_pkcs1_sign( rsa_context *ctx, int alg,
                    uchar *buf, uint buflen,
                    uchar *sig, uint siglen );

/*
 * Perform a public RSA and check the message digest.
 *
 *      ctx     points to an RSA public key
 *      alg     can be set to RSA_MD{2,4,5}, RSA_SHA1
 *              or 0 for all
 *      buf     buffer holding the data to be hashed
 *      buflen  length of the data
 *      sig     buffer holding the ciphertext
 *      siglen  must be the same as the modulus size
 *
 * Returns 0 if successful, or ERR_RSA_VERIFY_FAILED
 */
int rsa_pkcs1_verify( rsa_context *ctx, int alg,
                      uchar *buf, uint buflen,
                      uchar *sig, uint siglen );

/*
 * Free the components of an RSA key.
 */
void rsa_free( rsa_context *ctx );

/*
 * Checkup routine
 */
int rsa_self_test( void );

#endif
