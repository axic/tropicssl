#ifndef _MD5_H
#define _MD5_H

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
    ulong total[2];
    ulong state[4];
    uchar buffer[64];
}
md5_context;

/*
 * Core MD5 functions
 */
void md5_starts( md5_context *ctx );
void md5_update( md5_context *ctx, uchar *input, uint length );
void md5_finish( md5_context *ctx, uchar digest[16] );

/*
 * Output MD5(file contents), returns 0 if successful.
 */
int md5_file( char *filename, uchar digest[16] );

/*
 * Output MD5(buf)
 */
void md5_csum( uchar *buf, uint buflen, uchar digest[16] );

/*
 * Output HMAC-MD5(key,buf)
 */
void md5_hmac( uchar *key, uint keylen, uchar *buf, uint buflen,
               uchar digest[16] );

/*
 * Checkup routine
 */
int md5_self_test( void );

#ifdef __cplusplus
}
#endif

#endif /* md5.h */
