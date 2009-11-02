/**
 * \file aes.h
 */
#ifndef _AES_H
#define _AES_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

/**
 * \brief          AES context structure
 */
typedef struct
{
    ulong erk[64];     /*!< encryption round keys */
    ulong drk[64];     /*!< decryption round keys */
    int nr;            /*!< number of rounds      */
}
aes_context;

/**
 * \brief          AES key schedule
 *
 * \param ctx      AES context to be initialized
 * \param key      the secret key
 * \param keysize  must be 128, 192 or 256
 */
void aes_set_key( aes_context *ctx, uchar *key, int keysize );

/**
 * \brief          AES block encryption (ECB mode)
 *
 * \param ctx      AES context
 * \param input    plaintext  block
 * \param output   ciphertext block
 */
void aes_encrypt( aes_context *ctx, uchar input[16], uchar output[16] );

/**
 * \brief          AES block decryption (ECB mode)
 *
 * \param ctx      AES context
 * \param input    ciphertext block
 * \param output   plaintext  block
 */
void aes_decrypt( aes_context *ctx, uchar input[16], uchar output[16] );

/**
 * \brief          AES-CBC buffer encryption
 *
 * \param ctx      AES context
 * \param iv       initialization vector (modified after use)
 * \param input    buffer holding the plaintext
 * \param output   buffer holding the ciphertext
 * \param len      length of the data to be encrypted
 */
void aes_cbc_encrypt( aes_context *ctx, uchar iv[16],
                      uchar *input, uchar *output, int len );

/**
 * \brief          AES-CBC buffer decryption
 *
 * \param ctx      AES context
 * \param iv       initialization vector (modified after use)
 * \param input    buffer holding the ciphertext
 * \param output   buffer holding the plaintext
 * \param len      length of the data to be decrypted
 */
void aes_cbc_decrypt( aes_context *ctx, uchar iv[16],
                      uchar *input, uchar *output, int len );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int aes_self_test( void );

#ifdef __cplusplus
}
#endif

#endif /* aes.h */
