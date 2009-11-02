/**
 * \file sha1.h
 */
#ifndef _SHA1_H
#define _SHA1_H

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
 * \brief          SHA-1 context structure
 */
typedef struct
{
    ulong total[2];     /*!< number of bytes processed  */
    ulong state[5];     /*!< intermediate digest state  */
    uchar buffer[64];   /*!< data block being processed */
}
sha1_context;

/**
 * \brief          SHA-1 context setup
 *
 * \param ctx      SHA-1 context to be initialized
 */
void sha1_starts( sha1_context *ctx );

/**
 * \brief          SHA-1 process buffer
 *
 * \param ctx      SHA-1 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sha1_update( sha1_context *ctx, uchar *input, int ilen );

/**
 * \brief          SHA-1 final digest
 *
 * \param ctx      SHA-1 context
 * \param output   SHA-1 checksum result
 */
void sha1_finish( sha1_context *ctx, uchar output[20] );

/**
 * \brief          Output = SHA-1( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SHA-1 checksum result
 */
void sha1_csum( uchar *input, int ilen, uchar output[20] );

/**
 * \brief          Output = SHA-1( file contents )
 *
 * \param path     input file name
 * \param output   SHA-1 checksum result
 * \return         0 if successful, or 1 if fopen failed
 */
int sha1_file( char *path, uchar output[20] );

/**
 * \brief          Output = HMAC-SHA-1( input buffer, hmac key )
 *
 * \param key      HMAC secret key
 * \param klen     length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   HMAC-SHA-1 result
 */
void sha1_hmac( uchar *key, int klen, uchar *input, int ilen,
                uchar output[20] );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int sha1_self_test( void );

#ifdef __cplusplus
}
#endif

#endif /* sha1.h */
