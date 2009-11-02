/*
 *  An implementation of the ARCFOUR algorithm
 *
 *  Copyright (C) 2003-2006  Christophe Devine
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
/*
 *  The ARC4 algorithm was publicly disclosed on 94/09.
 *
 *  http://groups.google.com/group/sci.crypt/msg/10a300c9d21afca0
 */

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdio.h>

#include "arc4.h"

/*
 * ARC4 key schedule
 */
void arc4_setup( arc4_context *ctx, uchar *key, uint length )
{
    uint i, j, k, *m, a;

    ctx->x = 0;
    ctx->y = 0;
    m = ctx->m;

    for( i = 0; i < 256; i++ )
        m[i] = i;

    j = k = 0;

    for( i = 0; i < 256; i++ )
    {
        a = m[i];
        j = (uchar) ( j + a + key[k] );
        m[i] = m[j]; m[j] = a;
        if( ++k >= length ) k = 0;
    }
}

/*
 * ARC4 cipher function
 */
void arc4_crypt( arc4_context *ctx, uchar *data, uint length )
{
    uint i, x, y, *m, a, b;

    x = ctx->x;
    y = ctx->y;
    m = ctx->m;

    for( i = 0; i < length; i++ )
    {
        x = (uchar) ( x + 1 ); a = m[x];
        y = (uchar) ( y + a );
        m[x] = b = m[y];
        m[y] = a;
        data[i] ^= m[(uchar) ( a + b )];
    }

    ctx->x = x;
    ctx->y = y;
}

#ifdef SELF_TEST
/* 
 * ARC4 tests vectors as posted by Eric Rescorla
 */
static uchar arc4_test_key[3][8] =
{
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

static uchar arc4_test_pt[3][8] =
{
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

static uchar arc4_test_ct[3][8] =
{
    { 0x75, 0xB7, 0x87, 0x80, 0x99, 0xE0, 0xC5, 0x96 },
    { 0x74, 0x94, 0xC2, 0xE7, 0x10, 0x4B, 0x08, 0x79 },
    { 0xDE, 0x18, 0x89, 0x41, 0xA3, 0x37, 0x5D, 0x3A }
};

/*
 * Checkup routine
 */
int arc4_self_test( void )
{
    int i;
    uchar buf[8];
    arc4_context ctx;

    for( i = 0; i < 3; i++ )
    {
        printf( "  ARC4 test #%d: ", i + 1 );

        memcpy( buf, arc4_test_pt[i], 8 );

        arc4_setup( &ctx, arc4_test_key[i], 8 );
        arc4_crypt( &ctx, buf, 8 );

        if( memcmp( buf, arc4_test_ct[i], 8 ) != 0 )
        {
            printf( "failed\n" );
            return( 1 );
        }

        printf( "passed\n" );
    }

    printf( "\n" );
    return( 0 );
}
#else
int arc4_self_test( void )
{
    printf( "ARC4 self-test not available\n\n" );
    return( 1 );
}
#endif
