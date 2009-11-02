/**
 * \file rsa.h
 */
#ifndef _RSA_H
#define _RSA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bignum.h"

#define ERR_RSA_BAD_INPUT_DATA                  0x0300
#define ERR_RSA_INVALID_PADDING                 0x0310
#define ERR_RSA_KEY_GEN_FAILED                  0x0320
#define ERR_RSA_KEY_CHK_FAILED                  0x0330
#define ERR_RSA_KEY_RD_FAILED                   0x0340
#define ERR_RSA_KEY_WR_FAILED                   0x0350
#define ERR_RSA_PUBLIC_FAILED                   0x0360
#define ERR_RSA_PRIVATE_FAILED                  0x0370
#define ERR_RSA_VERIFY_FAILED                   0x0380

/*
 * PKCS#1 stuff
 */
#define RSA_RAW             0
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

typedef struct
{
    int ver;    /*!<  should be 0       */
    int len;    /*!<  size(N) in chars  */
    mpi N;      /*!<  public modulus    */
    mpi E;      /*!<  public exponent   */
    mpi D;      /*!<  private exponent  */

    mpi P;      /*!<  1st prime factor  */
    mpi Q;      /*!<  2nd prime factor  */
    mpi DP;     /*!<  D mod (P - 1)     */
    mpi DQ;     /*!<  D mod (Q - 1)     */
    mpi QP;     /*!<  inverse of Q % P  */

    mpi RN;     /*!<  cached R^2 mod N  */
    mpi RP;     /*!<  cached R^2 mod P  */
    mpi RQ;     /*!<  cached R^2 mod Q  */
}
rsa_context;

/**
 * \brief          Generate an RSA keypair
 *
 * \param ctx      RSA context to be initialized
 * \param nbits    size of the public key in bits
 * \param exponent public exponent (e.g., 65537)
 * \param rng_f    points to the RNG function
 * \param rng_d    points to the RNG data 
 *
 * \return         0 if successful, or an ERR_RSA_XXX error code
 */
int rsa_gen_key( rsa_context *ctx, int nbits, int exponent,
                 int (*rng_f)(void *), void *rng_d );

/**
 * \brief          Read the public key from a file
 *
 * \param ctx      RSA context to be initialized
 * \param f        Handle of the source file
 *
 * \return         0 if successful, or an ERR_RSA_XXX error code
 */
int rsa_read_public( rsa_context *ctx, FILE *f );

/**
 * \brief          Read the private key from a file
 *
 * \param ctx      RSA context to be initialized
 * \param f        Handle of the source file
 *
 * \return         0 if successful, or an ERR_RSA_XXX error code
 */
int rsa_read_private( rsa_context *ctx, FILE *f );

/**
 * \brief          Write the public key into a file
 *
 * \param ctx      RSA context holding the key
 * \param f        Handle of the destination file
 *
 * \return         0 if successful, or an ERR_RSA_XXX error code
 */
int rsa_write_public( rsa_context *ctx, FILE *f );

/**
 * \brief          Write the private key into a file
 *
 * \param ctx      RSA context holding the key
 * \param f        Handle of the destination file
 *
 * \return         0 if successful, or an ERR_RSA_XXX error code
 */
int rsa_write_private( rsa_context *ctx, FILE *f );

/**
 * \brief          Perform an RSA public key operation
 *
 * \return         0 if successful, or an ERR_RSA_XXX error code
 *
 * \note           This function does not take care of message
 *                 padding: both ilen and olen must be equal to
 *                 the modulus size (ctx->len). Also, be sure
 *                 to set input[0] = 0.
 */
int rsa_public( rsa_context   *ctx,
                unsigned char *input,  int ilen,
                unsigned char *output, int olen );

/**
 * \brief          Perform an RSA private key operation
 *
 * \return         0 if successful, or an ERR_RSA_XXX error code
 *
 * \note           This function does not take care of message
 *                 padding: both ilen and olen must be equal to
 *                 the modulus size (ctx->len). Also, be sure
 *                 to set input[0] = 0.
 */
int rsa_private( rsa_context   *ctx,
                 unsigned char *input,  int ilen,
                 unsigned char *output, int olen );

/**
 * \brief          Return 0 if the public key is valid,
 *                 or ERR_RSA_KEY_CHECK_FAILED
 */
int rsa_check_pubkey( rsa_context *ctx );

/**
 * \brief          Return 0 if the private key is valid,
 *                 or ERR_RSA_KEY_CHECK_FAILED
 */
int rsa_check_privkey( rsa_context *ctx );

/**
 * \brief          Add the PKCS#1 v1.5 padding and do a public RSA
 *
 * \param ctx      RSA context
 * \param input    buffer holding the data to be encrypted
 * \param ilen     length of the plaintext; cannot be longer
 *                 than the modulus, minus 3+8 for padding
 * \param output   buffer that will hold the ciphertext
 * \param olen     must be the same as the modulus size
 *                 (for example, 128 if RSA-1024 is used)
 *
 * \return         0 if successful, or an ERR_RSA_XXX error code
 */
int rsa_pkcs1_encrypt( rsa_context   *ctx,
                       unsigned char *input,  int ilen,
                       unsigned char *output, int olen );

/**
 * \brief          Do a private RSA, removes the PKCS#1 v1.5 padding
 *
 * \param ctx      RSA context
 * \param input    buffer holding the encrypted data
 * \param ilen     must be the same as the modulus size
 * \param output   buffer that will hold the plaintext
 * \param olen     size of output buffer, will be updated
 *                 to contain the length of the plaintext
 *
 * \return         0 if successful, or an ERR_RSA_XXX error code
 */
int rsa_pkcs1_decrypt( rsa_context   *ctx,
                       unsigned char *input,  int  ilen,
                       unsigned char *output, int *olen );

/**
 * \brief          Perform a private RSA to sign a message digest
 *
 * \param ctx      RSA context
 * \param alg_id   RSA_RAW, RSA_MD2/4/5 or RSA_SHA1
 * \param hash     buffer holding the message digest
 * \param hashlen  message digest length
 * \param sig      buffer that will hold the ciphertext
 * \param siglen   must be the same as the modulus size
 *                 (for example, 128 if RSA-1024 is used)
 *
 * \return         0 if the signing operation was successful,
 *                 or an ERR_RSA_XXX error code
 */
int rsa_pkcs1_sign( rsa_context   *ctx,  int alg_id,
                    unsigned char *hash, int hashlen,
                    unsigned char *sig,  int siglen );

/**
 * \brief          Perform a public RSA and check the message digest
 *
 * \param ctx      points to an RSA public key
 * \param alg_id   RSA_RAW, RSA_MD2/4/5 or RSA_SHA1
 * \param hash     buffer holding the message digest
 * \param hashlen  message digest length
 * \param sig      buffer holding the ciphertext
 * \param siglen   must be the same as the modulus size
 *
 * \return         0 if the verify operation was successful,
 *                 or an ERR_RSA_XXX error code
 */
int rsa_pkcs1_verify( rsa_context   *ctx,  int alg_id,
                      unsigned char *hash, int hashlen,
                      unsigned char *sig,  int siglen );

/**
 * \brief          Free the components of an RSA key
 */
void rsa_free( rsa_context *ctx );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int rsa_self_test( int verbose );

/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                "93A89813FBF3C4F8066D2D800F7C38A8" \
                "1AE31942917403FF4946B0A83D3D3E05" \
                "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
                "5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E   "10001"

#define RSA_D   "24BF6185468786FDD303083D25E64EFC" \
                "66CA472BC44D253102F8B4A9D3BFA750" \
                "91386C0077937FE33FA3252D28855837" \
                "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
                "DF79C5CE07EE72C7F123142198164234" \
                "CABB724CF78B8173B9F880FC86322407" \
                "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
                "071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P   "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
                "2C01CAD19EA484A87EA4377637E75500" \
                "FCB2005C5C7DD6EC4AC023CDA285D796" \
                "C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q   "C000DF51A7C77AE8D7C7370C1FF55B69" \
                "E211C2B9E5DB1ED0BF61D0D9899620F4" \
                "910E4168387E3C30AA1E00C339A79508" \
                "8452DD96A9A5EA5D9DCA68DA636032AF"

#define RSA_DP  "C1ACF567564274FB07A0BBAD5D26E298" \
                "3C94D22288ACD763FD8E5600ED4A702D" \
                "F84198A5F06C2E72236AE490C93F07F8" \
                "3CC559CD27BC2D1CA488811730BB5725"

#define RSA_DQ  "4959CBF6F8FEF750AEE6977C155579C7" \
                "D8AAEA56749EA28623272E4F7D0592AF" \
                "7C1F1313CAC9471B5C523BFE592F517B" \
                "407A1BD76C164B93DA2D32A383E58357"

#define RSA_QP  "9AE7FBC99546432DF71896FC239EADAE" \
                "F38D18D2B2F0E2DD275AA977E2BF4411" \
                "F5A3B2A5D33605AEBBCCBA7FEB9F2D2F" \
                "A74206CEC169D74BF5A8C50D6F48EA08"

#ifdef __cplusplus
}
#endif

#endif
