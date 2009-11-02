/**
 * \file sha2.h
 */
#ifndef _SHA2_H
#define _SHA2_H

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
 * \brief          SHA-256 context structure
 */
typedef struct
{
    ulong total[2];     /*!< number of bytes processed  */
    ulong state[8];     /*!< intermediate digest state  */
    uchar buffer[64];   /*!< data block being processed */
}
sha2_context;

/**
 * \brief          SHA-256 context setup
 *
 * \param ctx      SHA-256 context to be initialized
 */
void sha2_starts( sha2_context *ctx );

/**
 * \brief          SHA-256 process buffer
 *
 * \param ctx      SHA-256 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sha2_update( sha2_context *ctx, uchar *input, int ilen );

/**
 * \brief          SHA-256 final digest
 *
 * \param ctx      SHA-256 context
 * \param output   SHA-256 checksum result
 */
void sha2_finish( sha2_context *ctx, uchar output[32] );

/**
 * \brief          Output = SHA-256( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SHA-256 checksum result
 */
void sha2_csum( uchar *input, int ilen, uchar output[32] );

/**
 * \brief          Output = SHA-256( file contents )
 *
 * \param path     input file name
 * \param output   SHA-256 checksum result
 * \return         0 if successful, or 1 if fopen failed
 */
int sha2_file( char *path, uchar output[32] );

/**
 * \brief          Output = HMAC-SHA-256( input buffer, hmac key )
 *
 * \param key      HMAC secret key
 * \param klen     length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   HMAC-SHA-256 result
 */
void sha2_hmac( uchar *key, int klen, uchar *input, int ilen,
                uchar output[32] );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int sha2_self_test( void );

#ifdef __cplusplus
}
#endif

#endif /* sha2.h */
