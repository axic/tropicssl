#ifndef _DES_H
#define _DES_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

typedef struct
{
    ulong esk[32];     /* DES encryption subkeys */
    ulong dsk[32];     /* DES decryption subkeys */
}
des_context;

typedef struct
{
    ulong esk[96];     /* Triple-DES encryption subkeys */
    ulong dsk[96];     /* Triple-DES decryption subkeys */
}
des3_context;

/*
 * DES key schedule
 */
void des_set_key( des_context *ctx, uchar key[8] );

/*
 * DES 64-bit block encryption (ECB)
 */
void des_encrypt( des_context *ctx, uchar input[8], uchar output[8] );

/*
 * DES 64-bit block decryption (ECB)
 */
void des_decrypt( des_context *ctx, uchar input[8], uchar output[8] );

/*
 * DES-CBC encryption
 */
void des_cbc_encrypt( des_context *ctx, uchar iv[8],
                      uchar *input, uchar *output, uint len );

/*
 * DES-CBC decryption
 */
void des_cbc_decrypt( des_context *ctx, uchar iv[8],
                      uchar *input, uchar *output, uint len );

/*
 * Triple-DES key schedule (112-bit)
 */
void des3_set_2keys( des3_context *ctx, uchar key[16] );

/*
 * Triple-DES key schedule (168-bit)
 */
void des3_set_3keys( des3_context *ctx, uchar key[24] );

/*
 * Triple-DES 64-bit block encryption (ECB)
 */
void des3_encrypt( des3_context *ctx, uchar input[8], uchar output[8] );

/*
 * Triple-DES 64-bit block decryption (ECB)
 */
void des3_decrypt( des3_context *ctx, uchar input[8], uchar output[8] );

/*
 * 3DES-CBC encryption
 */
void des3_cbc_encrypt( des3_context *ctx, uchar iv[8],
                       uchar *input, uchar *output, uint len );

/*
 * 3DES-CBC decryption
 */
void des3_cbc_decrypt( des3_context *ctx, uchar iv[8],
                       uchar *input, uchar *output, uint len );

/*
 * Checkup routine
 */
int des_self_test( void );

#ifdef __cplusplus
}
#endif

#endif /* des.h */
