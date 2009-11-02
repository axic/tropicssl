#ifndef _HAVEGE_H
#define _HAVEGE_H

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

#define COLLECT_SIZE    1024
#define COLLECT_TIME       3

typedef struct
{
    ulong PT1, PT2;
    ulong WALK[8192];
    ulong pool[COLLECT_SIZE];
    uint offset;
}
havege_state;

/*
 * HAVEGE initialization phase
 */
void havege_init( havege_state *hs );

/*
 * Returns a random unsigned long.
 */
ulong havege_rand( void *rng_state );

#endif /* havege.h */
