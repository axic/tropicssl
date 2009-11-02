/*
 *  HAVEGE: HArdware Volatile Entropy Gathering and Expansion
 *
 *  Copyright (C) 2006  Andre Seznec, Olivier Rochecouste
 *
 *  Contact: seznec(at)irisa_dot_fr - orocheco(at)irisa_dot_fr
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
#ifndef _HAVEGE_H
#define _HAVEGE_H

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

#define COLLECT_SIZE    1024
#define COLLECT_TIME       2

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
