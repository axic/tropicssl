/**
 * \file md4.h
 */
#ifndef _MD4_H
#define _MD4_H

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
 * \brief          MD4 context structure
 */
typedef struct
{
    ulong total[2];     /*!< number of bytes processed  */
    ulong state[4];     /*!< intermediate digest state  */
    uchar buffer[64];   /*!< data block being processed */
}
md4_context;

/**
 * \brief          MD4 context setup
 *
 * \param ctx      MD4 context to be initialized
 */
void md4_starts( md4_context *ctx );

/**
 * \brief          MD4 process buffer
 *
 * \param ctx      MD4 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void md4_update( md4_context *ctx, uchar *input, int ilen );

/**
 * \brief          MD4 final digest
 *
 * \param ctx      MD4 context
 * \param output   MD4 checksum result
 */
void md4_finish( md4_context *ctx, uchar output[16] );

/**
 * \brief          Output = MD4( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   MD4 checksum result
 */
void md4_csum( uchar *input, int ilen, uchar output[16] );

/**
 * \brief          Output = MD4( file contents )
 *
 * \param path     input file name
 * \param output   MD4 checksum result
 * \return         0 if successful, or 1 if fopen failed
 */
int md4_file( char *path, uchar output[16] );

/**
 * \brief          Output = HMAC-MD4( input buffer, hmac key )
 *
 * \param key      HMAC secret key
 * \param klen     length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   HMAC-MD4 result
 */
void md4_hmac( uchar *key, int klen, uchar *input, int ilen,
               uchar output[16] );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int md4_self_test( void );

#ifdef __cplusplus
}
#endif

#endif /* md4.h */
