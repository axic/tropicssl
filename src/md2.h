#ifndef _MD2_H
#define _MD2_H

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

typedef struct
{
    uchar state[48];
    uchar cksum[16];
    uchar buffer[16];
    uint left;
}
md2_context;

/*
 * Core MD2 functions
 */
void md2_starts( md2_context *ctx );
void md2_update( md2_context *ctx, uchar *input, uint length );
void md2_finish( md2_context *ctx, uchar digest[16] );

/*
 * Output MD5(file contents), returns 0 if successful.
 */
int md2_file( char *filename, uchar digest[16] );

/*
 * Output MD2(buf)
 */
void md2_csum( uchar *buf, uint buflen, uchar digest[16] );

/*
 * Output HMAC-MD2(buf,key)
 */
void md2_hmac( uchar *buf, uint buflen, uchar *key, uint keylen,
               uchar digest[16] );

/*
 * Checkup routine
 */
int md2_self_test( void );

#endif /* md2.h */
