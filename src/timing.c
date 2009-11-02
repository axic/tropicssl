/*
 *  Portable interface to the CPU cycle counter
 *
 *  Copyright (C) 2003-2006  Christophe Devine, Brian Gladman
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License, version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include "timing.h"

#ifdef WIN32
#include <windows.h>
#include <winbase.h>

struct _hr_time
{
    LARGE_INTEGER start;
};
#else
#include <sys/time.h>
#include <time.h>

struct _hr_time
{
    struct timeval start;
};
#endif

#if defined(_MSC_VER) && defined(_M_IX86) || defined(__WATCOMC__)

unsigned long hardclock( void )
{
    unsigned long tsc;
    __asm   rdtsc
    __asm   mov  [tsc], eax
    return( tsc );
}

#else
#if defined(__i386__)

unsigned long hardclock( void )
{
#ifdef HAVE_RDTSC
    unsigned long tsc;
    asm( "rdtsc" : "=a" (tsc) );
    return( tsc );
#else
    struct timeval tv;
    gettimeofday( &tv, NULL );
    return( tv.tv_usec );
#endif
}

#else
#if defined(__x86_64__)

unsigned long hardclock( void )
{
    unsigned long tsc;
    asm( "rdtsc" : "=a" (tsc) ); 
    return( tsc );
}

#else
#if defined(__sparc__)

unsigned long hardclock( void )
{
    unsigned long tick;
    asm( "rd %%tick, %0" : "=r" (tick) );
    return( tick );
}

#else
#if defined(__alpha__)

unsigned long hardclock( void )
{
    unsigned long cc;
    asm( "rpcc %0" : "=r" (cc) );
    return( cc & 0xFFFFFFFF );
}

#else
#if defined(__ia64__)

unsigned long hardclock( void )
{
    unsigned long itc;
    asm( "mov %0 = ar.itc" : "=r" (itc) );
    return( itc );
}

#else
#if defined(__powerpc__) || defined(__ppc__)

unsigned long hardclock( void )
{
    unsigned long tbl, tbu0, tbu1;

    do
    {
        asm( "mftbu %0" : "=r" (tbu0) );
        asm( "mftb  %0" : "=r" (tbl ) );
        asm( "mftbu %0" : "=r" (tbu1) );
    }
    while( tbu0 != tbu1 );

    return( tbl );
}

#else

unsigned long hardclock( void )
{
    struct timeval tv;
    gettimeofday( &tv, NULL );
    return( tv.tv_usec );
}

#endif
#endif
#endif
#endif
#endif
#endif
#endif

#ifdef WIN32

float set_timer( struct hr_time *val, int reset )
{
    float delta = 0.0f;
    LARGE_INTEGER offset, hfreq;
    struct _hr_time *t = (struct _hr_time *) val;

    QueryPerformanceCounter(  &offset );
    QueryPerformanceFrequency( &hfreq );

    delta = (float) ( offset.QuadPart - t->start.QuadPart ) /
            (float) hfreq.QuadPart;

    if( reset )
        QueryPerformanceCounter( &t->start );

    return( delta );
}

#else

float set_timer( struct hr_time *val, int reset )
{
    float delta;
    struct timeval offset;
    struct _hr_time *t = (struct _hr_time *) val;

    gettimeofday( &offset, NULL );

    delta = (float) ( offset.tv_sec  - t->start.tv_sec  )
          + (float) ( offset.tv_usec - t->start.tv_usec ) / 1.0e6;

    if( reset )
    {
        t->start.tv_sec  = offset.tv_sec;
        t->start.tv_usec = offset.tv_usec;
    }

    return( delta );
}

#endif
