#ifndef _ARC4_H
#define _ARC4_H

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
    uint x, y, m[256];
}
arc4_context;

/*
 * ARC4 key schedule
 */
void arc4_setup( arc4_context *ctx, uchar *key, uint length );

/*
 * ARC4 cipher function
 */
void arc4_crypt( arc4_context *ctx, uchar *data, uint length );

/*
 * Checkup routine
 */
int arc4_self_test( void );

#ifdef __cplusplus
}
#endif

#endif /* arc4.h */
