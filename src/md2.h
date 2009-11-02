/**
 * \file md2.h
 */
#ifndef _MD2_H
#define _MD2_H

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
 * \brief          MD2 context structure
 */
typedef struct
{
    uchar state[48];    /*!< intermediate digest state  */
    uchar cksum[16];    /*!< checksum of the data block */
    uchar buffer[16];   /*!< data block being processed */
    int left;           /*!< amount of data in buffer   */
}
md2_context;

/**
 * \brief          MD2 context setup
 *
 * \param ctx      MD2 context to be initialized
 */
void md2_starts( md2_context *ctx );

/**
 * \brief          MD2 process buffer
 *
 * \param ctx      MD2 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void md2_update( md2_context *ctx, uchar *input, int ilen );

/**
 * \brief          MD2 final digest
 *
 * \param ctx      MD2 context
 * \param output   MD2 checksum result
 */
void md2_finish( md2_context *ctx, uchar output[16] );

/**
 * \brief          Output = MD2( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   MD2 checksum result
 */
void md2_csum( uchar *input, int ilen, uchar output[16] );

/**
 * \brief          Output = MD2( file contents )
 *
 * \param path     input file name
 * \param output   MD2 checksum result
 * \return         0 if successful, or 1 if fopen failed
 */
int md2_file( char *path, uchar output[16] );

/**
 * \brief          Output = HMAC-MD2( input buffer, hmac key )
 *
 * \param key      HMAC secret key
 * \param klen     length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   HMAC-MD2 result
 */
void md2_hmac( uchar *key, int klen, uchar *input, int ilen,
               uchar output[16] );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int md2_self_test( void );

#ifdef __cplusplus
}
#endif

#endif /* md2.h */
