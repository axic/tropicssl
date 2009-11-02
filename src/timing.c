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

#ifdef WIN32
#include <windows.h>
#include <winbase.h>

struct hr_time
{
    LARGE_INTEGER start, hfreq;
};
#else
#include <sys/time.h>
#include <time.h>
       
struct hr_time
{
    struct timeval start;
};
#endif

#ifdef _MSC_VER
typedef __int64 uint64;
#else
typedef unsigned long long uint64;
#endif

#if defined(_MSC_VER) && defined(_M_IX86) || defined(__WATCOMC__)

uint64 hardclock( void )
{
    volatile uint64 tsc;

    __asm
    {   
        rdtsc
        lea     ecx, [tsc]
        mov     [ecx], eax
        mov     [ecx + 4], edx
    }
    return( tsc );
}

#endif

#if defined(__i386__)

uint64 hardclock( void )
{
    volatile uint64 tsc;
    asm volatile( "rdtsc" : "=A" (tsc) );
    return( tsc );
}

#endif

#if defined(__sparc__)

uint64 hardclock( void )
{
    unsigned long tick;
    asm volatile( "rd %%tick, %0" : "=r" (tick) );
    return( tick );
}

#endif

#if defined(__alpha__)

uint64 hardclock( void )
{
    unsigned long cc;
    asm volatile( "rpcc %0" : "=r" (cc) );
    return( cc & 0xFFFFFFFF );
}

#endif

#if defined(__x86_64__)

uint64 hardclock( void )
{
    unsigned long a, d;
    asm volatile( "rdtsc" : "=a" (a), "=d" (d) ); 
    return( ( (uint64) d ) << 32 | a );
}

#endif

#if defined(__ia64__)

uint64 hardclock( void )
{
    uint64 itc;
    asm volatile( "mov %0 = ar.itc" : "=r" (itc) );
    return( itc );
}

#endif

#if defined(__powerpc__) || defined(__ppc__)

uint64 hardclock( void )
{
    unsigned long tbl, tbu0, tbu1;

    do
    {
        asm volatile( "mftbu %0" : "=r" (tbu0) );
        asm volatile( "mftb  %0" : "=r" (tbl ) );
        asm volatile( "mftbu %0" : "=r" (tbu1) );
    }
    while( tbu0 != tbu1 );

    return( ( (uint64) tbu0 ) << 32 | tbl );
}

#endif

#ifdef WIN32

float set_timer( void *timer_val, int reset )
{
    float delta = 0.0f;
    LARGE_INTEGER offset;
    struct hr_time *t = timer_val;

    QueryPerformanceCounter( &offset );

    if( t->hfreq.QuadPart )
    {
        delta = (float) ( offset.QuadPart - t->start.QuadPart ) /
                (float) t->hfreq.QuadPart;
    }

    if( reset )
    {
        QueryPerformanceFrequency( &t->hfreq );
        QueryPerformanceCounter( &t->start );
    }

    return( delta );
}

#else

float set_timer( void *timer_val, int reset )
{
    float delta;
    struct timeval offset;
    struct hr_time *t = timer_val;

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
