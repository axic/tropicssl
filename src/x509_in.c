/*
 *  X.509 certificate and private key decoding
 *
 *  Copyright (C) 2006  Christophe Devine
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
 *  The ITU-T X.509 standard defines a certificat format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc2459.txt
 *  http://www.ietf.org/rfc/rfc3279.txt
 *
 *  ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-1v2.asc
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 */

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "x509.h"
#include "rsa.h"
#include "mpi.h"
#include "md5.h"
#include "des.h"
#include "base64.h"

/* 
 * ASN.1 DER decoding routines
 */
int asn1_get_len( uchar **p, uchar *end, uint *len )
{
    if( ( end - *p ) < 1 )
        return( ERR_ASN1_OUT_OF_DATA );

    if( ( **p & 0x80 ) == 0 )
        *len = *(*p)++;
    else
    {
        switch( **p & 0x7F )
        {
        case 1:
            if( ( end - *p ) < 2 )
                return( ERR_ASN1_OUT_OF_DATA );

            *len = (*p)[1];
            (*p) += 2;
            break;

        case 2:
            if( ( end - *p ) < 3 )
                return( ERR_ASN1_OUT_OF_DATA );

            *len = ( (*p)[1] << 8 ) | (*p)[2];
            (*p) += 3;
            break;

        default:
            return( ERR_ASN1_INVALID_LENGTH );
            break;
        }
    }

    if( *len > (uint) ( end - *p ) )
        return( ERR_ASN1_OUT_OF_DATA );

    return( 0 );
}

int asn1_get_tag( uchar **p, uchar *end, uint *len, uint tag )
{
    if( ( end - *p ) < 1 )
        return( ERR_ASN1_OUT_OF_DATA );

    if( **p != tag )
        return( ERR_ASN1_UNEXPECTED_TAG );

    (*p)++;

    return( asn1_get_len( p, end, len ) );
}

int asn1_get_bool( uchar **p, uchar *end, uint *val )
{
    int ret;
    uint len;

    if( ( ret = asn1_get_tag( p, end, &len, ASN1_BOOLEAN ) ) != 0 )
        return( ret );

    if( len != 1 )
        return( ERR_ASN1_INVALID_LENGTH );

    *val = ( **p != 0 ) ? 1 : 0;
    (*p)++;

    return( 0 );
}

int asn1_get_int( uchar **p, uchar *end, uint *val )
{
    int ret;
    uint len;

    if( ( ret = asn1_get_tag( p, end, &len, ASN1_INTEGER ) ) != 0 )
        return( ret );

    if( len > sizeof( uint ) || ( **p & 0x80 ) != 0 )
        return( ERR_ASN1_INVALID_LENGTH );

    *val = 0;

    while( len-- > 0 )
    {
        *val = ( *val << 8 ) | **p;
        (*p)++;
    }

    return( 0 );
}

int asn1_get_mpi( uchar **p, uchar *end, mpi *X )
{
    int ret;
    uint len;

    if( ( ret = asn1_get_tag( p, end, &len, ASN1_INTEGER ) ) != 0 )
        return( ret );

    ret = mpi_import( X, *p, len );

    *p += len;

    return( ret );
}

/* 
 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 */
int x509_get_version( uchar **p, uchar *end, uint *ver )
{
    int ret;
    uint len;

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONTEXT_SPECIFIC | ASN1_CONSTRUCTED | 0 ) ) != 0 )
    {
        if( ret == ERR_ASN1_UNEXPECTED_TAG )
            return( *ver = 0 );

        return( ret );
    }

    end = *p + len;

    if( ( ret = asn1_get_int( p, end, ver ) ) != 0 )
        return( ERR_X509_CERT_INVALID_VERSION | ret );

    if( *p != end )
        return( ERR_X509_CERT_INVALID_VERSION |
                ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/* 
 *  CertificateSerialNumber  ::=  INTEGER
 */
int x509_get_serial( uchar **p, uchar *end, x509_buf *serial )
{
    int ret;

    if( ( end - *p ) < 1 )
        return( ERR_X509_CERT_INVALID_SERIAL |
                ERR_ASN1_OUT_OF_DATA );

    if( **p != ( ASN1_CONTEXT_SPECIFIC | ASN1_PRIMITIVE | 2 ) &&
        **p !=   ASN1_INTEGER )
        return( ERR_X509_CERT_INVALID_SERIAL |
                ERR_ASN1_UNEXPECTED_TAG );

    serial->tag = *(*p)++;

    if( ( ret = asn1_get_len( p, end, &serial->len ) ) != 0 )
        return( ERR_X509_CERT_INVALID_SERIAL | ret );

    serial->p = *p;
    *p += serial->len;

    return( 0 );
}

/* 
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
int x509_get_alg( uchar **p, uchar *end, x509_buf *alg )
{
    int ret;
    uint len;

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( ERR_X509_CERT_INVALID_ALG | ret );

    end = *p + len;
    alg->tag = **p;

    if( ( ret = asn1_get_tag( p, end, &alg->len, ASN1_OID ) ) != 0 )
        return( ERR_X509_CERT_INVALID_ALG | ret );

    alg->p = *p;
    *p += alg->len;

    if( *p == end )
        return( 0 );

    /*
     * we assume the algorithm parameters must be NULL
     */
    if( ( ret = asn1_get_tag( p, end, &len, ASN1_NULL ) ) != 0 )
        return( ERR_X509_CERT_INVALID_ALG | ret );

    if( *p != end )
        return( ERR_X509_CERT_INVALID_ALG |
                ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/* 
 *  RelativeDistinguishedName ::=
 *    SET OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 */
int x509_get_name( uchar **p, uchar *end, x509_name *cur )
{
    int ret;
    uint len;
    uchar *end2;
    x509_buf *oid;
    x509_buf *val;

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SET ) ) != 0 )
        return( ERR_X509_CERT_INVALID_NAME | ret );

    end2 = end;
    end  = *p + len;

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( ERR_X509_CERT_INVALID_NAME | ret );

    if( *p + len != end )
        return( ERR_X509_CERT_INVALID_NAME |
                ERR_ASN1_LENGTH_MISMATCH );

    oid = &cur->oid;
    oid->tag = **p;

    if( ( ret = asn1_get_tag( p, end, &oid->len, ASN1_OID ) ) != 0 )
        return( ERR_X509_CERT_INVALID_NAME | ret );

    oid->p = *p;
    *p += oid->len;

    if( ( end - *p ) < 1 )
        return( ERR_X509_CERT_INVALID_NAME |
                ERR_ASN1_OUT_OF_DATA );

    if( **p != ASN1_BMP_STRING && **p != ASN1_UTF8_STRING      &&
        **p != ASN1_T61_STRING && **p != ASN1_PRINTABLE_STRING &&
        **p != ASN1_IA5_STRING && **p != ASN1_UNIVERSAL_STRING )
        return( ERR_X509_CERT_INVALID_NAME |
                ERR_ASN1_UNEXPECTED_TAG );

    val = &cur->val;
    val->tag = *(*p)++;

    if( ( ret = asn1_get_len( p, end, &val->len ) ) != 0 )
        return( ERR_X509_CERT_INVALID_NAME | ret );

    val->p = *p;
    *p += val->len;

    cur->next = NULL;

    if( *p != end )
        return( ERR_X509_CERT_INVALID_NAME |
                ERR_ASN1_LENGTH_MISMATCH );

    /*
     * recurse until end of SEQUENCE is reached
     */
    if( *p == end2 )
        return( 0 );

    cur->next = (x509_name *) malloc(
         sizeof( x509_name ) );

    if( cur->next == NULL )
        return( 1 );

    return( x509_get_name( p, end2, cur->next ) );
}

/* 
 *  Validity ::= SEQUENCE {
 *       notBefore      Time,
 *       notAfter       Time }
 *
 *  Time ::= CHOICE {
 *       utcTime        UTCTime,
 *       generalTime    GeneralizedTime }
 */
int x509_get_dates( uchar **p, uchar *end,
                    x509_time *from, x509_time *to )
{
    int ret;
    uint len;
    char date[64];

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( ERR_X509_CERT_INVALID_DATE | ret );

    end = *p + len;

    /*
     * TODO: also handle GeneralizedTime
     */
    if( ( ret = asn1_get_tag( p, end, &len, ASN1_UTC_TIME ) ) != 0 )
        return( ERR_X509_CERT_INVALID_DATE | ret );

    memset( date,  0, sizeof( date ) );
    memcpy( date, *p, ( len < sizeof( date ) - 1 ) ?
                        len : sizeof( date ) - 1 );

    if( sscanf( date, "%2d%2d%2d%2d%2d%2d",
                &from->year, &from->mon, &from->day,
                &from->hour, &from->min, &from->sec ) < 5 )
        return( ERR_X509_CERT_INVALID_DATE );

    from->year += 100 * ( from->year < 90 );
    from->year += 1900;

    *p += len;

    if( ( ret = asn1_get_tag( p, end, &len, ASN1_UTC_TIME ) ) != 0 )
        return( ERR_X509_CERT_INVALID_DATE | ret );

    memset( date,  0, sizeof( date ) );
    memcpy( date, *p, ( len < sizeof( date ) - 1 ) ?
                        len : sizeof( date ) - 1 );

    if( sscanf( date, "%2d%2d%2d%2d%2d%2d",
                &to->year, &to->mon, &to->day,
                &to->hour, &to->min, &to->sec ) < 5 ) 
        return( ERR_X509_CERT_INVALID_DATE );

    to->year += 100 * ( to->year < 90 );
    to->year += 1900;

    *p += len;

    if( *p != end )
        return( ERR_X509_CERT_INVALID_DATE |
                ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/* 
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING }
 */
int x509_get_pubkey( uchar **p, uchar *end,
                     x509_buf *pk_alg_oid, mpi *N, mpi *E )
{
    int ret;
    uint len;
    uchar *end2;

    if( ( ret = x509_get_alg( p, end, pk_alg_oid ) ) != 0 )
        return( ret );

    /*
     * only RSA public keys handled at this time
     */
    if( pk_alg_oid->len != 9 ||
        memcmp( pk_alg_oid->p, OID_PKCS1_RSA, 9 ) != 0 )
        return( ERR_X509_CERT_UNKNOWN_PK_ALG );

    if( ( ret = asn1_get_tag( p, end, &len, ASN1_BIT_STRING ) ) != 0 )
        return( ERR_X509_CERT_INVALID_PUBKEY | ret );

    if( ( end - *p ) < 1 )
        return( ERR_X509_CERT_INVALID_PUBKEY |
                ERR_ASN1_OUT_OF_DATA );

    end2 = *p + len;

    if( *(*p)++ != 0 )
        return( ERR_X509_CERT_INVALID_PUBKEY );

    /*
     *  RSAPublicKey ::= SEQUENCE {
     *      modulus           INTEGER,  -- n
     *      publicExponent    INTEGER   -- e
     *  }
     */
    if( ( ret = asn1_get_tag( p, end2, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( ERR_X509_CERT_INVALID_PUBKEY | ret );

    if( *p + len != end2 )
        return( ERR_X509_CERT_INVALID_PUBKEY |
                ERR_ASN1_LENGTH_MISMATCH );

    if( ( ret = asn1_get_mpi( p, end2, N ) ) != 0 ||
        ( ret = asn1_get_mpi( p, end2, E ) ) != 0 )
        return( ERR_X509_CERT_INVALID_PUBKEY | ret );

    if( *p != end )
        return( ERR_X509_CERT_INVALID_PUBKEY |
                ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

int x509_get_sig( uchar **p, uchar *end, x509_buf *sig )
{
    int ret;
    uint len;

    sig->tag = **p;

    if( ( ret = asn1_get_tag( p, end, &len, ASN1_BIT_STRING ) ) != 0 )
        return( ERR_X509_CERT_INVALID_SIGNATURE | ret );

    if( --len < 1 || *(*p)++ != 0 )
        return( ERR_X509_CERT_INVALID_SIGNATURE );

    sig->len = len;
    sig->p = *p;

    *p += len;

    return( 0 );
}

/* 
 * X.509 v2/v3 unique identifier (not parsed)
 */
int x509_get_uid( uchar **p, uchar *end, x509_buf *uid, int n )
{
    int ret;

    if( *p == end )
        return( 0 );

    uid->tag = **p;

    if( ( ret = asn1_get_tag( p, end, &uid->len,
            ASN1_CONTEXT_SPECIFIC | ASN1_CONSTRUCTED | n ) ) != 0 )
    {
        if( ret == ERR_ASN1_UNEXPECTED_TAG )
            return( 0 );

        return( ret );
    }

    uid->p = *p;
    *p += uid->len;

    return( 0 );
}

/* 
 * X.509 v3 extensions (only BasicConstraints are parsed)
 */
int x509_get_ext( uchar **p, uchar *end, x509_buf *ext,
                  uint *ca_istrue, uint *max_pathlen )
{
    int ret;
    uint is_critical = 1;
    uint is_cacert = 0;
    uint len;
    uchar *end2;

    if( *p == end )
        return( 0 );

    ext->tag = **p;

    if( ( ret = asn1_get_tag( p, end, &ext->len,
            ASN1_CONTEXT_SPECIFIC | ASN1_CONSTRUCTED | 3 ) ) != 0 )
    {
        if( ret == ERR_ASN1_UNEXPECTED_TAG )
            return( 0 );

        return( ret );
    }

    ext->p = *p;
    end = *p + ext->len;

    /*
     * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     *
     * Extension  ::=  SEQUENCE  {
     *      extnID      OBJECT IDENTIFIER,
     *      critical    BOOLEAN DEFAULT FALSE,
     *      extnValue   OCTET STRING  }
     */
    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( ERR_X509_CERT_INVALID_EXTENSIONS | ret );

    if( end != *p + len )
        return( ERR_X509_CERT_INVALID_EXTENSIONS |
                ERR_ASN1_LENGTH_MISMATCH );

    while( *p < end )
    {
        if( ( ret = asn1_get_tag( p, end, &len,
                ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
            return( ERR_X509_CERT_INVALID_EXTENSIONS | ret );

        if( memcmp( *p, "\x06\x03\x55\x1D\x13", 5 ) != 0 )
        {
            *p += len;
            continue;
        }

        *p += 5;

        if( ( ret = asn1_get_bool( p, end, &is_critical ) ) != 0 &&
            ( ret != ERR_ASN1_UNEXPECTED_TAG ) )
            return( ERR_X509_CERT_INVALID_EXTENSIONS | ret );

        if( ( ret = asn1_get_tag( p, end, &len,
                ASN1_OCTET_STRING ) ) != 0 )
            return( ERR_X509_CERT_INVALID_EXTENSIONS | ret );

        /*
         * BasicConstraints ::= SEQUENCE {
         *      cA                      BOOLEAN DEFAULT FALSE,
         *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
         */
        end2 = *p + len;

        if( ( ret = asn1_get_tag( p, end2, &len,
                ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
            return( ERR_X509_CERT_INVALID_EXTENSIONS | ret );

        if( ( ret = asn1_get_bool( p, end2, &is_cacert ) ) != 0 )
            return( ERR_X509_CERT_INVALID_EXTENSIONS | ret );

        if( *p == end2 )
            continue;

        if( ( ret = asn1_get_int( p, end2, max_pathlen ) ) != 0 )
            return( ERR_X509_CERT_INVALID_EXTENSIONS | ret );

        if( *p != end2 )
            return( ERR_X509_CERT_INVALID_EXTENSIONS |
                    ERR_ASN1_LENGTH_MISMATCH );

        max_pathlen++;
    }

    if( *p != end )
        return( ERR_X509_CERT_INVALID_EXTENSIONS |
                ERR_ASN1_LENGTH_MISMATCH );

    *ca_istrue = is_critical & is_cacert;

    return( 0 );
}

/*
 * Parse one or more certificate and add them to the chain.
 */
int x509_add_certs( x509_cert *chain, uchar *buf, uint buflen )
{
    int ret;
    uint len;
    uchar *s1, *s2;
    uchar *p, *end;
    x509_cert *crt;

    crt = chain;

    while( crt->version != 0 )
        crt = crt->next;

    /*
     * check if the certificate is encoded in base64
     */
    s1 = (uchar *) strstr( (char *) buf,
        "-----BEGIN CERTIFICATE-----" );

    if( s1 != NULL )
    {
        s2 = (uchar *) strstr( (char *) buf,
            "-----END CERTIFICATE-----" );

        if( s2 == NULL || s2 <= s1 )
            return( ERR_X509_CERT_INVALID_PEM );

        s1 += 27;
        if( *s1 == '\r' ) s1++;
        if( *s1 == '\n' ) s1++;
            else return( ERR_X509_CERT_INVALID_PEM );

        /*
         * get the DER data length and decode the buffer
         */
        ret = base64_decode( NULL, &len, s1, s2 - s1 );

        if( ret == ERR_BASE64_INVALID_CHARACTER )
            return( ERR_X509_CERT_INVALID_PEM | ret );

        if( ( p = (uchar *) malloc( len ) ) == NULL )
            return( 1 );
            
        if( ( ret = base64_decode( p, &len, s1, s2 - s1 ) ) != 0 )
        {
            free( p );
            return( ERR_X509_CERT_INVALID_PEM | ret );
        }

        /*
         * update the buffer size and offset
         */
        s2 += 25;
        if( *s2 == '\r' ) s2++;
        if( *s2 == '\n' ) s2++;
            else return( ERR_X509_CERT_INVALID_PEM );

        buflen -= s2 - buf;
        buf = s2;
    }
    else
    {
        /*
         * nope, copy the raw DER data
         */
        p = (uchar *) malloc( len = buflen );

        if( p == NULL )
            return( 1 );

        memcpy( p, buf, buflen );

        buflen = 0;
    }

    crt->raw.p = p;
    crt->raw.len = len;
    end = p + len;

    /*
     * Certificate  ::=  SEQUENCE  {
     *      tbsCertificate       TBSCertificate,
     *      signatureAlgorithm   AlgorithmIdentifier,
     *      signatureValue       BIT STRING  }
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_free_cert( crt );
        return( ERR_X509_CERT_INVALID_FORMAT );
    }

    if( len != (uint) ( end - p ) )
    {
        x509_free_cert( crt );
        return( ERR_X509_CERT_INVALID_FORMAT |
                ERR_ASN1_LENGTH_MISMATCH );
    }

    /*
     * TBSCertificate  ::=  SEQUENCE  {
     */
    crt->tbs.p = p;

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_free_cert( crt );
        return( ERR_X509_CERT_INVALID_FORMAT | ret );
    }

    end = p + len;
    crt->tbs.len = end - crt->tbs.p;

    /*
     * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     *
     * CertificateSerialNumber  ::=  INTEGER
     *
     * signature            AlgorithmIdentifier
     */
    if( ( ret = x509_get_version( &p, end, &crt->version ) ) != 0 ||
        ( ret = x509_get_serial(  &p, end, &crt->serial  ) ) != 0 ||
        ( ret = x509_get_alg(  &p, end, &crt->sig_oid1   ) ) != 0 )
    {
        x509_free_cert( crt );
        return( ret );
    }

    crt->version++;

    if( crt->version > 3 )
    {
        x509_free_cert( crt );
        return( ERR_X509_CERT_UNKNOWN_VERSION );
    }

    if( crt->sig_oid1.len != 9 ||
        memcmp( crt->sig_oid1.p, OID_PKCS1, 8 ) != 0 )
    {
        x509_free_cert( crt );
        return( ERR_X509_CERT_UNKNOWN_SIG_ALG );
    }

    if( crt->sig_oid1.p[8] < 2 ||
        crt->sig_oid1.p[8] > 5 )
    {
        x509_free_cert( crt );
        return( ERR_X509_CERT_UNKNOWN_SIG_ALG );
    }

    /*
     * issuer               Name
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_free_cert( crt );
        return( ERR_X509_CERT_INVALID_FORMAT | ret );
    }

    if( ( ret = x509_get_name( &p, p + len, &crt->issuer ) ) != 0 )
    {
        x509_free_cert( crt );
        return( ret );
    }

    /*
     * Validity ::= SEQUENCE {
     *      notBefore      Time,
     *      notAfter       Time }
     *
     */
    if( ( ret = x509_get_dates( &p, end, &crt->valid_from,
                                         &crt->valid_to ) ) != 0 )
    {
        x509_free_cert( crt );
        return( ret );
    }

    /*
     * subject              Name
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_free_cert( crt );
        return( ERR_X509_CERT_INVALID_FORMAT | ret );
    }

    if( ( ret = x509_get_name( &p, p + len, &crt->subject ) ) != 0 )
    {
        x509_free_cert( crt );
        return( ret );
    }

    /*
     * SubjectPublicKeyInfo  ::=  SEQUENCE
     *      algorithm            AlgorithmIdentifier,
     *      subjectPublicKey     BIT STRING  }
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_free_cert( crt );
        return( ERR_X509_CERT_INVALID_FORMAT | ret );
    }

    if( ( ret = x509_get_pubkey( &p, p + len, &crt->pk_oid,
                                 &crt->rsa.N, &crt->rsa.E ) ) != 0 )
    {
        x509_free_cert( crt );
        return( ret );
    }

    if( ( ret = rsa_check_pubkey( &crt->rsa ) ) != 0 )
    {
        x509_free_cert( crt );
        return( ret );
    }

    crt->rsa.len = crt->rsa.N.n * sizeof( ulong );

    /*
     *  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     *  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     *  extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                       -- If present, version shall be v3
     */

    if( crt->version == 2 || crt->version == 3 )
    {
        ret = x509_get_uid( &p, end, &crt->issuer_id,  1 );
        if( ret != 0 )
        {
            x509_free_cert( crt );
            return( ret );
        }
    }

    if( crt->version == 2 || crt->version == 3 )
    {
        ret = x509_get_uid( &p, end, &crt->subject_id,  2 );
        if( ret != 0 )
        {
            x509_free_cert( crt );
            return( ret );
        }
    }

    if( crt->version == 3 )
    {
        ret = x509_get_ext( &p, end, &crt->v3_ext,
                            &crt->ca_istrue, &crt->max_pathlen );
        if( ret != 0 )
        {
            x509_free_cert( crt );
            return( ret );
        }
    }

    if( p != end )
    {
        x509_free_cert( crt );
        return( ERR_X509_CERT_INVALID_FORMAT |
                ERR_ASN1_LENGTH_MISMATCH );
    }

    end = crt->raw.p + crt->raw.len;

    /*
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signatureValue       BIT STRING
     */
    if( ( ret = x509_get_alg( &p, end, &crt->sig_oid2 ) ) != 0 )
    {
        x509_free_cert( crt );
        return( ret );
    }

    if( memcmp( crt->sig_oid1.p, crt->sig_oid2.p, 9 ) != 0 )
    {
        x509_free_cert( crt );
        return( ERR_X509_CERT_SIG_MISMATCH );
    }

    if( ( ret = x509_get_sig( &p, end, &crt->sig ) ) != 0 )
    {
        x509_free_cert( crt );
        return( ret );
    }

    if( p != end )
    {
        x509_free_cert( crt );
        return( ERR_X509_CERT_INVALID_FORMAT |
                ERR_ASN1_LENGTH_MISMATCH );
    }

    crt->next = (x509_cert *) malloc( sizeof( x509_cert ) );

    if( crt->next == NULL )
    {
        x509_free_cert( crt );
        return( 1 );
    }

    crt = crt->next;
    memset( crt, 0, sizeof( x509_cert ) );

    if( buflen > 0 )
        return( x509_add_certs( crt, buf, buflen ) );

    return( 0 );
}

/*
 * Load a certificate from file, returns 0 if successful.
 */
int x509_read_crtfile( x509_cert *chain, char *filename )
{
    int ret;
    FILE *f;
    ulong len;
    uchar *buf;

    if( ( f = fopen( filename, "rb" ) ) == NULL )
        return( 1 );

    fseek( f, 0, SEEK_END ); len = ftell( f );
    fseek( f, 0, SEEK_SET );

    if( ( buf = (uchar *) malloc( len + 1 ) ) == NULL )
        return( 1 );

    if( fread( buf, 1, len, f ) != len )
    {
        fclose( f );
        free( buf );
        return( 1 );
    }

    buf[len] = '\0';

    ret = x509_add_certs( chain, buf, len );

    fclose( f );
    free( buf );

    return( ret );
}

/* 
 * Read a 16-byte hex string and convert it to binary.
 */
int x509_des3_getiv( uchar *s, uchar iv[8] )
{
    int i, j;

    memset( iv, 0, 8 );

    for( i = 0; i < 16; i++, s++ )
    {
        if( *s >= '0' && *s <= '9' ) j = *s - '0'; else
        if( *s >= 'A' && *s <= 'F' ) j = *s - '7'; else
        if( *s >= 'a' && *s <= 'f' ) j = *s - 'W'; else
            return( ERR_X509_KEY_INVALID_ENC_IV );

        if( (i & 1) != 0 )
            iv[i >> 1] |= j;
        else
            iv[i >> 1] |= j << 4;
    }

    return( 0 );
}

/* 
 * Decrypt with 3DES-CBC, using PBKDF1 for key derivation.
 */
void x509_des3_decrypt( uchar des3_iv[8], uchar *buf, uint buflen,
                                          uchar *pwd, uint pwdlen )
{
    md5_context md5_ctx;
    des3_context des3_ctx;
    uchar md5sum[16];
    uchar des3_key[24];

    /*
     * 3DES key[ 0..15] = MD5(pwd || IV)
     *      key[16..23] = MD5(pwd || IV || 3DES key[ 0..15])
     */
    md5_starts( &md5_ctx );
    md5_update( &md5_ctx, pwd, pwdlen );
    md5_update( &md5_ctx, des3_iv,  8 );
    md5_finish( &md5_ctx, md5sum );
    memcpy( des3_key, md5sum, 16 );

    md5_starts( &md5_ctx );
    md5_update( &md5_ctx, md5sum,  16 );
    md5_update( &md5_ctx, pwd, pwdlen );
    md5_update( &md5_ctx, des3_iv,  8 );
    md5_finish( &md5_ctx, md5sum );
    memcpy( des3_key + 16, md5sum, 8 );

    des3_set_3keys( &des3_ctx, des3_key );
    des3_cbc_decrypt( &des3_ctx, des3_iv, buf, buf, buflen );

    memset( & md5_ctx, 0, sizeof(  md5_ctx ) );
    memset( &des3_ctx, 0, sizeof( des3_ctx ) );
    memset( md5sum, 0, 16 );
    memset( des3_key, 0, 24 );
}

/*
 * Parse a DER-encoded private key file.
 */
int x509_parse_key( rsa_context *rsa, uchar *buf, uint buflen,
                                      uchar *pwd, uint pwdlen )
{
    int ret;
    uint len, enc;
    uchar *s1, *s2;
    uchar *p, *end;
    uchar des3_iv[8];

    s1 = (uchar *) strstr( (char *) buf,
        "-----BEGIN RSA PRIVATE KEY-----" );

    if( s1 != NULL )
    {
        s2 = (uchar *) strstr( (char *) buf,
            "-----END RSA PRIVATE KEY-----" );

        if( s2 == NULL || s2 <= s1 )
            return( ERR_X509_KEY_INVALID_PEM );

        s1 += 31;
        if( *s1 == '\r' ) s1++;
        if( *s1 == '\n' ) s1++;
            else return( ERR_X509_KEY_INVALID_PEM );

        enc = 0;

        if( memcmp( s1, "Proc-Type: 4,ENCRYPTED", 22 ) == 0 )
        {
            enc++;

            s1 += 22;
            if( *s1 == '\r' ) s1++;
            if( *s1 == '\n' ) s1++;
                else return( ERR_X509_KEY_INVALID_PEM );

            if( memcmp( s1, "DEK-Info: DES-EDE3-CBC,", 23 ) != 0 )
                return( ERR_X509_KEY_UNKNOWN_ENC_ALG );

            s1 += 23;
            if( x509_des3_getiv( s1, des3_iv ) != 0 )
                return( ERR_X509_KEY_INVALID_ENC_IV );

            s1 += 16;
            if( *s1 == '\r' ) s1++;
            if( *s1 == '\n' ) s1++;
                else return( ERR_X509_KEY_INVALID_PEM );
        }

        ret = base64_decode( NULL, &len, s1, s2 - s1 );

        if( ret == ERR_BASE64_INVALID_CHARACTER )
            return( ret | ERR_X509_KEY_INVALID_PEM );

        if( ( buf = (uchar *) malloc( len ) ) == NULL )
            return( 1 );

        if( ( ret = base64_decode( buf, &len, s1, s2 - s1 ) ) != 0 )
        {
            free( buf );
            return( ret | ERR_X509_KEY_INVALID_PEM );
        }

        buflen = len;

        if( enc != 0 )
        {
            if( pwd == NULL )
            {
                free( buf );
                return( ERR_X509_KEY_PASSWORD_REQUIRED );
            }

            x509_des3_decrypt( des3_iv, buf, buflen, pwd, pwdlen );

            if( buf[0] != 0x30 || buf[1] != 0x82 ||
                buf[4] != 0x02 || buf[5] != 0x01 )
            {
                free( buf );
                return( ERR_X509_KEY_PASSWORD_MISMATCH );
            }
        }
    }

    memset( rsa, 0, sizeof( rsa_context ) );

    p = buf;
    end = buf + buflen;

    /*
     *  RSAPrivateKey ::= SEQUENCE {
     *      version           Version,
     *      modulus           INTEGER,  -- n
     *      publicExponent    INTEGER,  -- e
     *      privateExponent   INTEGER,  -- d
     *      prime1            INTEGER,  -- p
     *      prime2            INTEGER,  -- q
     *      exponent1         INTEGER,  -- d mod (p-1)
     *      exponent2         INTEGER,  -- d mod (q-1)
     *      coefficient       INTEGER,  -- (inverse of q) mod p
     *      otherPrimeInfos   OtherPrimeInfos OPTIONAL
     *  }
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( ERR_X509_KEY_INVALID_FORMAT | ret );
    }

    end = p + len;

    if( ( ret = asn1_get_int( &p, end, &rsa->ver ) ) != 0 )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( ERR_X509_KEY_INVALID_FORMAT | ret );
    }

    if( rsa->ver != 0 )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( ret | ERR_X509_KEY_INVALID_VERSION );
    }

    if( ( ret = asn1_get_mpi( &p, end, &rsa->N  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->E  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->D  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->P  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->Q  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->DP ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->DQ ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->QP ) ) != 0 )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( ret | ERR_X509_KEY_INVALID_FORMAT );
    }

    rsa->len = rsa->N.n * sizeof( ulong );

    if( p != end )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( ERR_X509_KEY_INVALID_FORMAT |
                ERR_ASN1_LENGTH_MISMATCH );
    }

    if( ( ret = rsa_check_privkey( rsa ) ) != 0 )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( ret );
    }

    return( 0 );
}

/*
 * Load a private key from file, optionaly password-protected.
 */
int x509_read_keyfile( rsa_context *rsa, char *filename, char *password )
{
    int ret;
    FILE *f;
    ulong len;
    uchar *buf;

    if( ( f = fopen( filename, "rb" ) ) == NULL )
        return( 1 );

    fseek( f, 0, SEEK_END ); len = ftell( f );
    fseek( f, 0, SEEK_SET );

    if( ( buf = (uchar *) malloc( len + 1 ) ) == NULL )
        return( 1 );

    if( fread( buf, 1, len, f ) != len )
    {
        fclose( f );
        free( buf );
        return( 1 );
    }

    buf[len] = '\0';

    if( password == NULL )
        ret = x509_parse_key( rsa, buf, len, NULL, 0 );
    else
        ret = x509_parse_key( rsa, buf, len,
                (uchar *) password, strlen( password ) );

    fclose( f );
    free( buf );

    return( ret );
}

#if defined WIN32 && ! defined snprintf
#define snprintf _snprintf
#endif

/*
 * Store the DN in printable form into buf; no more
 * than (end - buf) characters will be written.
 */
int dn_gets( char *buf, char *end, x509_name *dn )
{
    uint i;
    uchar c;
    x509_name *name;
    char s[128], *p;

    memset( s, 0, sizeof( s ) );

    name = dn;
    p = buf;

    while( name != NULL )
    {
        if( name != dn )
            p += snprintf( p, end - p, ", " );

        if( memcmp( name->oid.p, OID_X520, 2 ) == 0 )
        {
            switch( name->oid.p[2] )
            {
            case X520_COMMON_NAME:
                p += snprintf( p, end - p, "CN=" ); break;

            case X520_COUNTRY:
                p += snprintf( p, end - p, "C="  ); break;

            case X520_LOCALITY:
                p += snprintf( p, end - p, "L="  ); break;

            case X520_STATE:
                p += snprintf( p, end - p, "ST=" ); break;

            case X520_ORGANIZATION:
                p += snprintf( p, end - p, "O="  ); break;

            case X520_ORG_UNIT:
                p += snprintf( p, end - p, "OU=" ); break;

            default:
                p += snprintf( p, end - p, "0x%02X=",
                               name->oid.p[2] );
                break;
            }
        }
        else if( memcmp( name->oid.p, OID_PKCS9, 8 ) == 0 )
        {
            switch( name->oid.p[8] )
            {
            case PKCS9_EMAIL:
                p += snprintf( p, end - p, "emailAddress=" ); break;

            default:
                p += snprintf( p, end - p, "0x%02X=",
                               name->oid.p[8] );
                break;
            }
        }
        else
            p += snprintf( p, end - p, "\?\?=" );

        for( i = 0; i < name->val.len; i++ )
        {
            if( i >= sizeof( s ) - 1 )
                break;

            c = name->val.p[i];
            if( c < 32 || c == 127 || ( c > 128 && c < 160 ) )
                 s[i] = '?';
            else s[i] = c;
        }
        s[i] = '\0';
        p += snprintf( p, end - p, "%s", s );
        name = name->next;
    }

    return( p - buf );
}

/*
 * Returns an informational string about the certificate,
 * or NULL if memory allocation failed.
 */
char *x509_cert_info( x509_cert *crt )
{
    uint i, n;
    char *buf, *p, *end;

    if( ( buf = (char *) malloc( 4096 ) ) == NULL )
        return( NULL );

    memset( buf, 0, 4096 );

    p = buf;
    end = buf + 4096 - 1;

    p += snprintf( p, end - p, "Cert. version : %d\n", crt->version );
    p += snprintf( p, end - p, "Serial Number : " );

    n = ( crt->serial.len <= 32 )
        ? crt->serial.len  : 32;

    for( i = 1; i < n; i++ )
        p += snprintf( p, end - p, "%02X%s",
                crt->serial.p[i], ( i < n - 1 ) ? ":" : "" );

    p += snprintf( p, end - p, "\nIssuer name   : " );
    p += dn_gets(  p, end, &crt->issuer  );

    p += snprintf( p, end - p, "\nSubject name  : " );
    p += dn_gets(  p, end, &crt->subject );

    p += snprintf( p, end - p, "\nIssued on     : " \
                   "%04d-%02d-%02d %02d:%02d:%02d",
                   crt->valid_from.year, crt->valid_from.mon,
                   crt->valid_from.day,  crt->valid_from.hour,
                   crt->valid_from.min,  crt->valid_from.sec );

    p += snprintf( p, end - p, "\nExpires on    : " \
                   "%04d-%02d-%02d %02d:%02d:%02d",
                   crt->valid_to.year, crt->valid_to.mon,
                   crt->valid_to.day,  crt->valid_to.hour,
                   crt->valid_to.min,  crt->valid_to.sec );

    p += snprintf( p, end - p, "\nSigned using  : RSA+" );

    switch( crt->sig_oid1.p[8] )
    {
        case RSA_MD2 : p += snprintf( p, end - p, "MD2"  ); break;
        case RSA_MD4 : p += snprintf( p, end - p, "MD4"  ); break;
        case RSA_MD5 : p += snprintf( p, end - p, "MD5"  ); break;
        case RSA_SHA1: p += snprintf( p, end - p, "SHA1" ); break;
        default: p += snprintf( p, end - p, "???"  ); break;
    }

    p += snprintf( p, end - p, "\nRSA key size  : %u bits\n",
                   crt->rsa.N.n * (int) sizeof( ulong ) * 8 );

    return( buf );
}

/*
 * Returns 0 if certificate is still valid, or BADCERT_HAS_EXPIRED.
 */
int x509_is_cert_expired( x509_cert *crt )
{
    struct tm *lt;
    time_t tt;

    tt = time( NULL );
    lt = localtime( &tt );

    if( lt->tm_year  > crt->valid_to.year - 1900 )
        return( BADCERT_HAS_EXPIRED );

    if( lt->tm_year == crt->valid_to.year - 1900 &&
        lt->tm_mon   > crt->valid_to.mon  - 1 )
        return( BADCERT_HAS_EXPIRED );

    if( lt->tm_year == crt->valid_to.year - 1900 &&
        lt->tm_mon  == crt->valid_to.mon  - 1    &&
        lt->tm_mday  > crt->valid_to.day )
        return( BADCERT_HAS_EXPIRED );

    return( 0 );
}


/*
 * Verify the certificate validity; set cn to NULL if the subject
 * CommonName must not be verified.
 *
 * Returns 0 if successful or ERR_X509_SIG_VERIFY_FAILED,
 * in which case *flags will have one or more of the following
 * values set:
 *      BADCERT_HAS_EXPIRED
 *      BADCERT_CN_MISMATCH
 *      BADCERT_NOT_TRUSTED
 */
int x509_verify_cert( x509_cert *crt, x509_cert *trust_ca,
                      char *cn, uint *flags )
{
    char *dn_end;
    char crt_dn[256];
    char ca_dn[256];
    x509_cert *cur;
    x509_name *name;
    uint pathlen = 1;

    *flags = x509_is_cert_expired( crt );

    if( cn != NULL )
    {
        name = &crt->subject;

        while( name != NULL )
        {
            if( memcmp( name->oid.p, "\x55\x04\x03", 3 ) == 0 &&
                memcmp( name->val.p, cn, strlen( cn )  ) == 0 )
                break;

            name = name->next;
        }

        if( name == NULL )
            *flags |= BADCERT_CN_MISMATCH;
    }

    *flags |= BADCERT_NOT_TRUSTED;

    /*
     * Iterate upwards in the given cert chain,
     * ignoring any upper cert with CA != TRUE.
     */
    cur = crt->next;

    while( cur->version != 0 )
    {
        memset( crt_dn, 0, sizeof( crt_dn ) );
        dn_end = crt_dn +  sizeof( crt_dn ) - 1;
        dn_gets( crt_dn, dn_end, &crt->issuer );

        memset( ca_dn, 0, sizeof( ca_dn ) );
        dn_end = ca_dn +  sizeof( ca_dn ) - 1;
        dn_gets( ca_dn, dn_end, &cur->subject );

        if( strcmp( ca_dn, crt_dn ) != 0 || cur->ca_istrue == 0 )
        {
            cur = cur->next;
            continue;
        }

        if( rsa_pkcs1_verify( &cur->rsa, crt->sig_oid1.p[8],
                               crt->tbs.p, crt->tbs.len,
                               crt->sig.p, crt->sig.len ) != 0 )
            return( ERR_X509_SIG_VERIFY_FAILED );

        pathlen++;

        crt = cur;
        cur = crt->next;
    }

    /*
     * Atempt to validate topmost cert with our CA chain.
     */
    memset( crt_dn, 0, sizeof( crt_dn ) );
    dn_end = crt_dn +  sizeof( crt_dn ) - 1;
    dn_gets( crt_dn, dn_end, &crt->issuer );

    while( trust_ca->version != 0 )
    {
        memset( ca_dn, 0, sizeof( ca_dn ) );
        dn_end = ca_dn +  sizeof( ca_dn ) - 1;
        dn_gets( ca_dn, dn_end, &trust_ca->subject );

        if( strcmp( ca_dn, crt_dn ) != 0 )
        {
            trust_ca = trust_ca->next;
            continue;
        }

        if( trust_ca->max_pathlen > 0 &&
            trust_ca->max_pathlen < pathlen )
            return( ERR_X509_SIG_VERIFY_FAILED );

        if( rsa_pkcs1_verify( &trust_ca->rsa, crt->sig_oid1.p[8],
                               crt->tbs.p, crt->tbs.len,
                               crt->sig.p, crt->sig.len ) != 0 )
            return( ERR_X509_SIG_VERIFY_FAILED );

        break;
    }

    if( trust_ca->version == 0 )
        return( ERR_X509_SIG_VERIFY_FAILED );

    *flags &= ~BADCERT_NOT_TRUSTED;

    return( 0 );
}

/*
 * Unallocate all certificate data
 */
void x509_free_cert( x509_cert *crt )
{
    x509_name *cur, *prv;

    cur = crt->issuer.next;

    while( cur != NULL )
    {
        prv = cur;
        cur = cur->next;
        free( prv );
    }

    cur = crt->subject.next;

    while( cur != NULL )
    {
        prv = cur;
        cur = cur->next;
        free( prv );
    }

    rsa_free( &crt->rsa );

    if( crt->raw.p != NULL )
        free( crt->raw.p );
}

#ifdef SELF_TEST

char ca_crt[] =
"-----BEGIN CERTIFICATE-----\r\n" \
"MIIDtTCCAp2gAwIBAgIJAMqzUV2oEqS0MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV\r\n" \
"BAYTAkZSMQ4wDAYDVQQIEwVQYXJpczEOMAwGA1UEChMFWHlTU0wxFjAUBgNVBAMT\r\n" \
"DVh5U1NMIFRlc3QgQ0EwHhcNMDYwOTA3MTAwNjQ1WhcNMTYwOTA3MTAwNjQ1WjBF\r\n" \
"MQswCQYDVQQGEwJGUjEOMAwGA1UECBMFUGFyaXMxDjAMBgNVBAoTBVh5U1NMMRYw\r\n" \
"FAYDVQQDEw1YeVNTTCBUZXN0IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\r\n" \
"CgKCAQEA0G35JaBcnjqkYahLLO5bHIcviLkY9fXW8bqkwP4YgCyzWyEWnr1Rs8vU\r\n" \
"uZQHwZBi/RqAL3SNL08cLUg/rEbvrieGXn0EXQCndKnrHr+xT6WSC2q897caqYei\r\n" \
"WNbZ92w5wiHjaxDwJZJ9IOvgzxP4T+IDgbc5nOHOfcdSnoF/56wX36xnyMwoRFS5\r\n" \
"Iy8iSnYDhsoMk1KKVxq9JVVHTSn7CpnnSD3ttsZCxyutQTNY0Bj13tlPFjBmlRf/\r\n" \
"ZkzS9JuzDVM35FnD5YD3ifVVNyyJhG3svdPUyzgXY8kfFWAkW/L2u0xJULlACnyd\r\n" \
"gLKevD+p7AUTvK9zCv+IZPYU7aLWwQIDAQABo4GnMIGkMB0GA1UdDgQWBBSSjays\r\n" \
"p1RiK3AwCxXuY6PVx2NxmTB1BgNVHSMEbjBsgBSSjaysp1RiK3AwCxXuY6PVx2Nx\r\n" \
"maFJpEcwRTELMAkGA1UEBhMCRlIxDjAMBgNVBAgTBVBhcmlzMQ4wDAYDVQQKEwVY\r\n" \
"eVNTTDEWMBQGA1UEAxMNWHlTU0wgVGVzdCBDQYIJAMqzUV2oEqS0MAwGA1UdEwQF\r\n" \
"MAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAIZwds/iFDj1FeQxAxCUrPHz6LwyoLQQ\r\n" \
"/5rfBj5xecl1v0ImjtDXR7+Oetw1JIiIC+0JFsq5POCQ9XYFj/4CnZafX544q97Z\r\n" \
"DeN7uSw7Xclgp8KlssCXEDs8WvK8kc7klzshsLgKsgI3/oQ4JOI2erqkzYjh8PCg\r\n" \
"l47EVJz/j/B2lh9FwZb+VwZ2ERYGrFNy9AiyzUZHYj1C0DAzThwfwSuQ4mxZPKaC\r\n" \
"qrEB8MeVYi5rUfuk34Ly0eTFgFW65ISl9P81VENtHSypshww4s5Kpnk3lTNm5NcQ\r\n" \
"xEfM98D7jE5uZ2KDELFjGE7sviVcmfTzg7oKmE8NevUBJQQC974qjYA=\r\n" \
"-----END CERTIFICATE-----\r\n";

char ca_key[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n" \
"Proc-Type: 4,ENCRYPTED\r\n" \
"DEK-Info: DES-EDE3-CBC,598E2069A441E75F\r\n\r\n" \
"T2K5wBKsPQ8fgHMreYy2MMk7wKNcgbdt1Vwu1CFP8tDEarkpif7BKJInwLzptZK/\r\n" \
"5MQbaKe+y/SBL/SNbiI9Z4mCrsVLU5qlm/E/Hf1rlNCoEpD3o59uovv3EOPm2bSz\r\n" \
"JMge+sO8uRaHiOz+QSZpwhn+Wfh0a9g1IYSO8tcVCbyzBeXb5QD5dNgBR/n3vHs+\r\n" \
"Rg67+6A4o1I6B8xx746l/rNkbV2PvyqbgSoCIpc2v5g1QMIZsQ6JZe5pgWFrFLNt\r\n" \
"eHPKjxEIr/o8DyZ+bJGN09V8WkxG0/gMfSvPvPJ1IC0JYzpT1oQzce5zdYt9adnF\r\n" \
"vpWu1eHbWuC9cIUl690Dv8+r8IxDU9NfGqk79nH9hlC7RJ8geka+3MoBFtyhsILD\r\n" \
"GJWcgkeJRRahCwWqqWgd4YJxiL/CKksJZBQpqu1r822VkpoyRgFftPGnnZHrJEfc\r\n" \
"LQoKeDC8TFDnPC59KTFfmDIQzrfaK1gf+OoUiE+JGZIWNG1DyfX4M3qfFXpQtojn\r\n" \
"kUrmAODFCqKm7TKe7Y6O7zLHufH4NGPe30AjLB7R0cIKy93V35PlARNNqNeJKK4J\r\n" \
"5KzYp1xXN+1OOrAgaz7DfWR969SKM469QJalRIuXTw+42SoA5/Ol+JPMkx3uIl68\r\n" \
"22nTKF8JPwMTxfaHwtTPSn9q+IIjm1g9EGtfPn8fzwYw8hWjGq8UeR2kpFMKViia\r\n" \
"y3iQwCNU+D65DDMzVNflBZo49de1el43uh4FaF8ilkeX9dudLG3p9eA8DEvbNT8M\r\n" \
"J3TxTaQpQGrN27MMQjTJGF+LFb9xHaN7S9SCGAk5iPkpucFni5L8udm8mrLHggWo\r\n" \
"CQHHIippQ2PC7sQeXrZbgcnK2hc0sq9zLqI4CyxBjr05oaAWj0lVzWW2VA0G62eq\r\n" \
"p2gUc473t+d3VS+cV7JcjZdF8hopxf8KD/YFEYvNuWPOoYzMzCwmpdaLqhtz7zzp\r\n" \
"qxiTFajupMFqHckobo/C7+WJSFxvaYZNNqTj+Pf0TPbVuEXkr8LDXi7XnSJCyj9B\r\n" \
"UZzZSlZj0cpnmnkBAhs67vZZR75kz3p/31ZbHvadeQOBOQ+X8QLlBkU3FDxgsy2r\r\n" \
"fdnPaDP8MXi5+WfkSlhhsdmBhOllQ0IYOkhgmiSA0N3v2xqAesC4uJY1pUvvNTjA\r\n" \
"gkxAfhzOOxq8kYiBZ9MXKiLoWltLhWqEnnorGSs9yPV9+nvnLf2pJ2XeLLv8KDux\r\n" \
"q0BAmkTqt9imMBNP4KDvTg//OzdIFuNN1z7ux8fqcIUhi2/KH3N5U5vnKBGktwJ6\r\n" \
"jIohUThQjNw2AHpuwj4jvyZBnm+9KaFVwmKGB6bpa0rMzW0q8eOqHcdzkELfBDNB\r\n" \
"3PM8a9HZj8gxbVl7ydrM6lhkermQuejjt1fO26nmOT9Ycogcel7JWGBWreBNKbPD\r\n" \
"KV2LsVv1SGU2RYN5CrHsqjvLS4wlNL+nXxwBhJkF870FeTcNBnrIRKh9zJth/F6r\r\n" \
"fJEtqLt8ue/q7insHFm+Rlo2nTqBzoz3vxt5tmU4Bke9x1+ZtVULj0ZUv3eQoVlo\r\n" \
"ZTnzYwWzo32ZsLFIbQZuUw682o/cOpi02QRgeEEGikhWY8IQknEcMLnUoQ5/GuRn\r\n" \
"-----END RSA PRIVATE KEY-----\r\n";

char ca_pwd[] = "test";

char clt_crt[] =
"-----BEGIN CERTIFICATE-----\r\n" \
"MIIDATCCAekCCQDTl3duLhemVjANBgkqhkiG9w0BAQUFADBFMQswCQYDVQQGEwJG\r\n" \
"UjEOMAwGA1UECBMFUGFyaXMxDjAMBgNVBAoTBVh5U1NMMRYwFAYDVQQDEw1YeVNT\r\n" \
"TCBUZXN0IENBMB4XDTA2MDkwNzEwMDczM1oXDTA3MDkwNzEwMDczM1owQDELMAkG\r\n" \
"A1UEBhMCRlIxDjAMBgNVBAgTBVBhcmlzMQ4wDAYDVQQKEwVYeVNTTDERMA8GA1UE\r\n" \
"AxMISm9lIFVzZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuDKrr\r\n" \
"1pVTmwZ7aexKE7okTbJb1M/h9k79fYiZGulOmomrEDO0YIm8mqyPakPGKPRO/95F\r\n" \
"PrfVyJckb4M58oYhAXpLLnq8+tqKnJgUQmQOrSKmzteN+RaGeqYnxeuwIYIxSjeR\r\n" \
"9S5vfKo5j0KeKakDQtrE0qaK4+QiQry9mwg1PHiErxnFqVypXkpMbN7rcjIjFNSq\r\n" \
"AVYcxgZ3oJmfqX+FITaOY1EIeQnMBNQokHXSZ4gLN5O0VF0YoUA+lWojdBJtT8CB\r\n" \
"Q12/cxJC59ctJi5xMvcdgjbNvxj33jwvOy+TksxRO4jg2v2it7s4GL3fbVRk/RzP\r\n" \
"/EoGrwtKeNbp0iq5AgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAAIeRXGDO6vlVgIz\r\n" \
"+XNeIAv5JgX7FxpCnmEajf/lKGuDFDqEsXcHtvEjOZLBn8kHGCUC2+LaVSC4y5xd\r\n" \
"twGyliU1/t5PjgrkeaNxZ7jXy5+UYBsQmA33F+AX/I4laJ8IvLc4D+6U34HJ33Az\r\n" \
"nLBf4xG8ClQWyRXG8PNh5N4XWmT6iSdRrogEF/ez0+LX/Dv4F66HAXLZNkci3a7k\r\n" \
"SN7GtTEPa3A9wFM0R9eodz78uqG6bGRMXVkw1YUe/8gqgRWdv0lLczM8TZdeXeIw\r\n" \
"Ho8f29A2P6F2T8frrt+dtuq8ehPKDIE8pbVg6GGvUTrSdiVxLeXCCvT3/Cfvr3Gi\r\n" \
"p8z9/ks=\r\n" \
"-----END CERTIFICATE-----\r\n";

/*
 * Checkup routine
 */
int x509_self_test( void )
{
    int ret;
    uint flags;
    x509_cert cacert;
    x509_cert cltcert;
    rsa_context rsa;
    
    printf( "  X.509 certificate load: " );

    memset( &cltcert, 0, sizeof( x509_cert ) );

    ret = x509_add_certs( &cltcert, (uchar *) clt_crt,
                                      strlen( clt_crt ) );
    if( ret != 0 )
    {
        printf( "failed\n" );
        return( ret );
    }

    memset( &cacert, 0, sizeof( x509_cert ) );

    ret = x509_add_certs( &cacert, (uchar *) ca_crt,
                                     strlen( ca_crt ) );
    if( ret != 0 )
    {
        printf( "failed\n" );
        return( ret );
    }

    printf( "passed\n  X.509 private key load: " );

    ret = x509_parse_key( &rsa, (uchar *) ca_key, strlen( ca_key ),
                                (uchar *) ca_pwd, strlen( ca_pwd ) );
    if( ret != 0 )
    {
        printf( "failed\n" );
        return( ret );
    }

    printf( "passed\n  X.509 signature verify: ");
    ret = x509_verify_cert( &cltcert, &cacert, "Joe User", &flags );
    if( ret != 0 )
    {
        printf( "failed\n" );
        return( ret );
    }

    printf( "passed\n\n" );
    return( 0 );
}
#else
int x509_self_test( void )
{
    printf( "X.509 self-test not available\n\n" );
    return( 1 );
}
#endif
