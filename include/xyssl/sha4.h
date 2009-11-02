/**
 * \file sha4.h
 */
#ifndef _SHA4_H
#define _SHA4_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER) || defined(__WATCOMC__)
#define UL64(x) x##ui64
#define uint64 unsigned __int64
#else
#define UL64(x) x##ULL
#define uint64 unsigned long long
#endif

/**
 * \brief          SHA-512 context structure
 */
typedef struct
{
    uint64 total[2];            /*!< number of bytes processed  */
    uint64 state[8];            /*!< intermediate digest state  */
    unsigned char buffer[128];  /*!< data block being processed */
    unsigned char ipad[64];     /*!< HMAC: inner padding        */
    unsigned char opad[64];     /*!< HMAC: outer padding        */
    int is384;                  /*!< 0 if SHA-512, 1 if SHA-384 */
}
sha4_context;

/**
 * \brief          SHA-512 context setup
 *
 * \param ctx      context to be initialized
 * \param is384    0 = use SHA512, 1 = use SHA384
 */
void sha4_starts( sha4_context *ctx, int is384 );

/**
 * \brief          SHA-512 process buffer
 *
 * \param ctx      SHA-512 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sha4_update( sha4_context *ctx, unsigned char *input, int ilen );

/**
 * \brief          SHA-512 final digest
 *
 * \param ctx      SHA-512 context
 * \param output   SHA-384/512 checksum result
 */
void sha4_finish( sha4_context *ctx, unsigned char *output );

/**
 * \brief          Output = SHA-512( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SHA-384/512 checksum result
 * \param is384    0 = use SHA512, 1 = use SHA384
 */
void sha4( unsigned char *input,  int ilen,
           unsigned char *output, int is384 );

/**
 * \brief          Output = SHA-512( file contents )
 *
 * \param path     input file name
 * \param output   SHA-384/512 checksum result
 * \param is384    0 = use SHA512, 1 = use SHA384
 *
 * \return         0 if successful, 1 if fopen failed,
 *                 or 2 if fread failed
 */
int sha4_file( char *path, unsigned char *output, int is384 );

/**
 * \brief          SHA-512 HMAC context setup
 *
 * \param ctx      HMAC context to be initialized
 * \param is384    0 = use SHA512, 1 = use SHA384
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 */
void sha4_hmac_starts( sha4_context *ctx,  int is384,
                       unsigned char *key, int keylen );

/**
 * \brief          SHA-512 HMAC process buffer
 *
 * \param ctx      HMAC context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sha4_hmac_update( sha4_context *ctx,
                       unsigned char *input, int ilen );

/**
 * \brief          SHA-512 HMAC final digest
 *
 * \param ctx      HMAC context
 * \param output   SHA-384/512 HMAC checksum result
 */
void sha4_hmac_finish( sha4_context *ctx, unsigned char *output );

/**
 * \brief          Output = HMAC-SHA-512( hmac key, input buffer )
 *
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   HMAC-SHA-384/512 result
 * \param is384    0 = use SHA512, 1 = use SHA384
 */
void sha4_hmac( unsigned char *key,  int keylen,
                unsigned char *input,  int ilen,
                unsigned char *output, int is384 );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int sha4_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* sha4.h */
