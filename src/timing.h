#ifndef _TIMING_H
#define _TIMING_H

#ifdef __cplusplus
extern "C" {
#endif

struct hr_time
{
    unsigned char opaque[32];
};

/*
 * This function returns the CPU cycle counter value
 */
unsigned long hardclock( void );

/*
 * If reset != 0, the timer is restarted. Otherwise,
 * the elapsed time in seconds is returned.
 */
float set_timer( struct hr_time *val, int reset );

#ifdef __cplusplus
}
#endif

#endif /* timing.h */
