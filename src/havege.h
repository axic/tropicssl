/**
 * \file havege.h
 */
#ifndef _HAVEGE_H
#define _HAVEGE_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

#define COLLECT_SIZE 1024
#define COLLECT_TIME    3

/**
 * \brief          HAVEGE state structure
 */
typedef struct
{
    ulong PT1, PT2;
    ulong WALK[8192];
    ulong pool[COLLECT_SIZE];
    uint offset;
}
havege_state;

/**
 * \brief          HAVEGE initialization
 *
 * \param hs       HAVEGE state to be initialized
 */
void havege_init( havege_state *hs );

/**
 * \brief          HAVEGE rand function
 *
 * \param rng_st   HAVEGE state
 *
 * \return         A random unsigned long
 */
ulong havege_rand( void *rng_st );

#ifdef __cplusplus
}
#endif

#endif /* havege.h */
