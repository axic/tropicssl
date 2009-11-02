/* 
 * Copyright (c) 2006-2007, Christophe Devine
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer
 *       in the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of the XySSL nor the names of its contributors
 *       may be used to endorse or promote products derived from this
 *       software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdio.h>

#include "xyssl/md2.h"
#include "xyssl/md4.h"
#include "xyssl/md5.h"
#include "xyssl/sha1.h"
#include "xyssl/sha2.h"
#include "xyssl/arc4.h"
#include "xyssl/des.h"
#include "xyssl/aes.h"
#include "xyssl/bignum.h"
#include "xyssl/base64.h"
#include "xyssl/rsa.h"
#include "xyssl/x509.h"

int main( int argc, char *argv[] )
{
    int ret, v;

    if( argc == 2 && strcmp( argv[1], "-quiet" ) == 0 )
        v = 0;
    else
    {
        v = 1;
        printf( "\n" );
    }

    if( ( ret =    md2_self_test( v ) ) == 0 &&
        ( ret =    md4_self_test( v ) ) == 0 &&
        ( ret =    md5_self_test( v ) ) == 0 &&
        ( ret =   sha1_self_test( v ) ) == 0 &&
        ( ret =   sha2_self_test( v ) ) == 0 &&
        ( ret =   arc4_self_test( v ) ) == 0 &&
        ( ret =    des_self_test( v ) ) == 0 &&
        ( ret =    aes_self_test( v ) ) == 0 &&
        ( ret =    mpi_self_test( v ) ) == 0 &&
        ( ret = base64_self_test( v ) ) == 0 &&
        ( ret =    rsa_self_test( v ) ) == 0 &&
        ( ret =   x509_self_test( v ) ) == 0 )
    {
        if( v != 0 )
            printf( "  [ All tests passed ]\n" );
    }

    if( v != 0 )
    {
        printf( "\n" );
#ifdef WIN32
        printf( "  Press Enter to exit this program.\n" );
        fflush( stdout ); getchar();
#endif
    }

    return( ret );
}
