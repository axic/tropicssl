#ifndef _TIMING_H
#define _TIMING_H

#ifdef _MSC_VER
typedef __int64 uint64;
#else
typedef unsigned long long uint64;
#endif

struct hr_time
{
    unsigned char opaque[32];
};

uint64 hardclock( void );

float set_timer( void *timer_val, int reset );

#endif /* timing.h */
