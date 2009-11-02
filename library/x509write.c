/* 
 * Copyright (C) 2006-2007  Pascal Vizeli <pvizeli@yahoo.de>
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include "xyssl/x509.h"
#include "xyssl/base64.h"
#include "xyssl/des.h"
#include "xyssl/sha1.h"
#include "xyssl/md5.h"

#if !defined(NO_MD4)
#include "xyssl/md4.h"
#endif
#if !defined(NO_MD2)
#include "xyssl/md2.h"
#endif

#define and &&
#define or ||

static int x509_realloc_node(x509_node *node, size_t larger);
static int x509_free_node(x509_node *node);
static void x509_init_node(x509_node *node);
static int x509_write_file(x509_node *node, char *path, int format, const char* pem_prolog, const char* pem_epilog);

/*
 * evaluate how mani octet have this integer
 */
static int asn1_eval_octet(unsigned int digit)
{
    int i, byte; 

    for (byte = 4, i = 24; i >= 0; i -= 8, --byte)
        if (((digit >> i) & 0xFF) != 0)
            return byte;

    return 0;
}

/*
 * write the asn.1 lenght form into p
 */
static int asn1_add_len(unsigned int size, x509_node *node)
{
    if (size > 127) {

        /* long size */
        int byte = asn1_eval_octet(size);
        int i = 0;

        *(node->p) = 0x80 | byte & 0xff;
        ++node->p;

        for (i = byte; i > 0; --i) {
      
            *(node->p) = (size >> ((i - 1) * 8)) & 0xFF;
            ++node->p;
        }

    } else {

        /* short size */
        *(node->p) = size & 0xFF;
        if (size != 0)
            ++node->p;
    }

    return 0;
}

/*
 * write a ans.1 object into p
 */
static int asn1_add_obj(unsigned char *value, unsigned int size, int tag, 
        x509_node *node)
{
    int tl = 2;

    if (tag == ASN1_BIT_STRING)
        ++tl;

    if (size > 127)
        x509_realloc_node(node, (size_t) size + tl + asn1_eval_octet(size));
    else
        x509_realloc_node(node, (size_t) size + tl);

    if (node->data == NULL)
        return ERR_X509_MEMORY_ALLOC_FAILED;

    /* tag */
    *(node->p) = tag & 0xFF;
    ++node->p;

    /* len */
    if (tag == ASN1_BIT_STRING) {
        asn1_add_len((unsigned int) size + 1, node);
        *(node->p) = 0x00;
        ++node->p;
    } else {
        asn1_add_len((unsigned int) size, node);
    }

    /* value */
    if (size > 0) {

        memcpy(node->p, value, (size_t) size);
        if ((node->p += size -1) != node->end)
            return ERR_X509_POINT_ERROR;
    } else {
        /* make nothing -> NULL */
    }

    return 0;
}

/*
 * write a asn.1 conform integer object
 */
static int asn1_add_int(signed int value, x509_node *node)
{
    signed int i = 0, neg = 1;
    unsigned int byte, u_val = 0, tmp_val = 0;

    /* if negate? */
    if (value < 0) {
        neg = -1;
        u_val = ~value;
    } else {
        u_val = value;
    }

    byte = asn1_eval_octet(u_val);

    /* ASN.1 integer is signed! */
    if (byte < 4 and ((u_val >> ((byte -1) * 8)) & 0xFF) == 0x80)
        byte += 1;

    if (x509_realloc_node(node, (size_t) byte + 2) != 0)
        return ERR_X509_MEMORY_ALLOC_FAILED;

    /* tag */
    *(node->p) = ASN1_INTEGER;
    ++node->p;
    
    /* len */
    asn1_add_len(byte, node);

    /* value */
    for (i = byte; i > 0; --i) {

        tmp_val = (u_val >> ((i - 1) * 8)) & 0xFF;
        if (neg == 1)
            *(node->p) = tmp_val;
        else
            *(node->p) = ~tmp_val;

        if (i > 1)
          ++node->p;
    }

    if (node->p != node->end)
        return ERR_X509_POINT_ERROR;

    return 0;
}

/*
 * write a asn.1 conform mpi object
 */
static int asn1_add_mpi(mpi *value, int tag, x509_node *node)
{
    size_t size = (mpi_msb(value) / 8) + 1;
    unsigned char *buf;
    int buf_len = (int) size, tl = 2;

    if (tag == ASN1_BIT_STRING)
        ++tl;

    if (size > 127)
        x509_realloc_node(node, size + (size_t) tl +
            asn1_eval_octet((unsigned int)size));
    else
        x509_realloc_node(node, size + (size_t) tl);

    if (node->data == NULL)
        return ERR_X509_MEMORY_ALLOC_FAILED;

    buf = (unsigned char*) malloc(size);
    if (mpi_write_binary(value, buf, &buf_len) != 0)
        return ERR_MPI_BUFFER_TOO_SMALL;

    /* tag */
    *(node->p) = tag & 0xFF;
    ++node->p;

    /* len */
    if (tag == ASN1_BIT_STRING) {
        asn1_add_len((unsigned int) size + 1, node);
        *(node->p) = 0x00;
        ++node->p;
    } else {
        asn1_add_len((unsigned int) size, node);
    }

    /* value */
    memcpy(node->p, buf, size);
    free(buf);

    if ((node->p += (int) size -1) != node->end)
        return ERR_X509_POINT_ERROR;

    return 0;
}

/*
 * write a node into asn.1 conform object
 */
static int asn1_append_tag(x509_node *node, int tag)
{
    x509_node tmp;
    x509_init_node(&tmp);
    int tl = 2;

    if (tag == ASN1_BIT_STRING)
        ++tl;

    if (node->len > 127)
        x509_realloc_node(&tmp, node->len + (size_t) tl +
            asn1_eval_octet((unsigned int)node->len));
    else
        x509_realloc_node(&tmp, node->len + (size_t) tl);

    if (tmp.data == NULL)
        return ERR_X509_MEMORY_ALLOC_FAILED;

    /* tag */
    *(tmp.p) = tag & 0xFF;
    ++tmp.p;

    /* len */
    if (tag == ASN1_BIT_STRING) {
        asn1_add_len((unsigned int) node->len + 1, &tmp);
        *(tmp.p) = 0x00;
        ++tmp.p;
    } else {
        asn1_add_len((unsigned int) node->len, &tmp);
    }

    /* value */
    memcpy(tmp.p, node->data, node->len);

    /* good? */
    if ((tmp.p += (int) node->len -1) != tmp.end)
        return ERR_X509_POINT_ERROR;

    free(node->data);
    node->data = tmp.data;
    node->p = tmp.p;
    node->end = tmp.end;
    node->len = tmp.len;

    return 0;
}

/*
 * write nodes into a asn.1 object
 */
static int asn1_append_nodes(x509_node *node, int tag, int anz, ...)
{
    va_list ap;
    size_t size = 0;
    x509_node *tmp;
    int count;

    va_start(ap, anz);
    count = anz;

    while (count--) {

        tmp = va_arg(ap, x509_node*);
        if (tmp->data != NULL)
            size += tmp->len;
    }

    if ( size > 127) {
        if (x509_realloc_node(node, size + (size_t) 2 + 
                    asn1_eval_octet(size)) != 0)
            return ERR_X509_MEMORY_ALLOC_FAILED;
    } else {
        if (x509_realloc_node(node, size + (size_t) 2) != 0)
            return ERR_X509_MEMORY_ALLOC_FAILED;
    }

    /* tag */
    *(node->p) = tag & 0xFF;
    ++node->p;

    /* len */
    asn1_add_len(size, node);

    /* value */
    va_start(ap, anz);
    count = anz;

    while (count--) {

        tmp = va_arg(ap, x509_node*);
        if (tmp->data != NULL) {
            
            memcpy(node->p, tmp->data, tmp->len);
            if ((node->p += (int) tmp->len -1) != node->end)
                ++node->p;
        }
    }

    va_end(ap);
    return 0;
}

/*
 * write a ASN.1 conform object identifiere include a "tag"
 */
static int asn1_add_oid(x509_node *node, unsigned char *oid, size_t len, 
        int tag, int tag_val, unsigned char *value, size_t val_len)
{
    int ret;
    x509_node tmp;

    x509_init_node(&tmp);

    /* OBJECT IDENTIFIER */
    if ((ret = asn1_add_obj(oid, len, ASN1_OID, &tmp)) != 0)
        return ret;

    /* value */
    if ((ret = asn1_add_obj(value, val_len, tag_val, &tmp)) != 0)
        return ret;

    /* SET/SEQUENCE */
    if ((ret = asn1_append_nodes(node, tag, 1, &tmp)) != 0)
        return ret;

    x509_free_node(&tmp);
    return 0;
}

/*
 *  utcTime        UTCTime
 */
static int asn1_add_date_utc(unsigned char *time, x509_node *node)
{
    unsigned char date[13], *sp;
    x509_time xtime;
    int ret;

    sscanf(time, "%d-%d-%d %d:%d:%d", &xtime.year, &xtime.mon, &xtime.day,
        &xtime.hour, &xtime.min, &xtime.sec);

    /* convert to YY */
    if (xtime.year > 2000)
        xtime.year -= 2000;
    else
        xtime.year -= 1900;

    snprintf(date, 13, "%2d%2d%2d%2d%2d%2d", xtime.year, xtime.mon, xtime.day,
        xtime.hour, xtime.min, xtime.sec);

    /* replace ' ' to '0' */
    for (sp = date; *sp != '\0'; ++sp)
        if (*sp == '\x20')
            *sp = '\x30';

    date[12] = 'Z';

    if ((ret = asn1_add_obj(date, 13, ASN1_UTC_TIME, node)) != 0)
        return ret;

    return 0;
}

/*
 * serialize an rsa key into DER
 */

int x509_serialize_key(rsa_context *rsa, x509_node *node)
{
    int ret = 0; 
    memset(node,0,sizeof(x509_node));
    
    /* vers, n, e, d, p, q, dp, dq, pq */
    if ((ret = asn1_add_int(rsa->ver, node)) != 0)
        return ret;
    if ((ret = asn1_add_mpi(&rsa->N, ASN1_INTEGER, node)) != 0)
        return ret;
    if ((ret = asn1_add_mpi(&rsa->E, ASN1_INTEGER, node)) != 0)
        return ret;
    if ((ret = asn1_add_mpi(&rsa->D, ASN1_INTEGER, node)) != 0)
	return ret;
    if ((ret = asn1_add_mpi(&rsa->P, ASN1_INTEGER, node)) != 0)
	return ret;
    if ((ret = asn1_add_mpi(&rsa->Q, ASN1_INTEGER, node)) != 0)
	return ret;
    if ((ret = asn1_add_mpi(&rsa->DP, ASN1_INTEGER, node)) != 0)
	return ret;
    if ((ret = asn1_add_mpi(&rsa->DQ, ASN1_INTEGER, node)) != 0)
	return ret;
    if ((ret = asn1_add_mpi(&rsa->QP, ASN1_INTEGER, node)) != 0)
	return ret;
    if ((ret = asn1_append_tag(node, ASN1_CONSTRUCTED | ASN1_SEQUENCE)) != 0)
        return ret;
    
    return 0;
}

/*
 * write a der/pem encoded rsa private key into a file
 */
int x509_write_keyfile(rsa_context *rsa, unsigned char *path, int out_flag)
{
    int ret = 0;
    const char	key_beg[] = "-----BEGIN RSA PRIVATE KEY-----\n", 
                key_end[] = "-----END RSA PRIVATE KEY-----\n";
    x509_node node;

    memset(&node,0,sizeof(x509_node));
    if ((ret = x509_serialize_key(rsa,&node)) != 0)
	return ret;
    
    return x509_write_file(&node,path,out_flag,key_beg,key_end);
}


/*
 * reasize the memory for node
 */
static int x509_realloc_node(x509_node *node, size_t larger)
{
    /* init len */
    if (node->data == NULL) {
        node->len = 0;
        node->data = malloc(larger);
        if(node->data == NULL)
            return ERR_X509_MEMORY_ALLOC_FAILED;
    } else {
        /* realloc memory */
        if ((node->data = realloc(node->data, node->len + larger)) == NULL)
            return ERR_X509_MEMORY_ALLOC_FAILED;
    }

    /* init pointer */
    node->p = &node->data[node->len];
    node->len += larger;
    node->end = &node->data[node->len -1];

  return 0;
}

/*
 * init node
 */ 
static void x509_init_node(x509_node *node)
{
    memset(node, 0, sizeof(x509_node));
}

/*
 * clean memory
 */
static int x509_free_node(x509_node *node)
{
    free(node->data);
    node->p = NULL;
    node->end = NULL;
    node->len = 0;
}


/*
 * write a x509 certificate into file
 */
int x509_write_crtfile(x509_raw *chain, unsigned char *path, int out_flag)
{
    const char	cer_beg[] = "-----BEGIN CERTIFICATE-----\n", 
		cer_end[] = "-----END CERTIFICATE-----\n";
    
    return x509_write_file(&chain->raw, path, out_flag, cer_beg, cer_end);
}

/*
 * write an x509 file
 */
static int x509_write_file(x509_node *node, char *path, int format, const char* pem_prolog, const char* pem_epilog)
{
    FILE *ofstream; 
    int is_err = 1, buf_len, i, n;
    char* base_buf;
    
    if ((ofstream = fopen(path, "wb")) == NULL)
        return 1;
    
    switch (format) {
        case X509_OUTPUT_DER:
            if (fwrite(node->data, 1, node->len, ofstream) 
                    != node->len)
                is_err = -1;
            break;
        case X509_OUTPUT_PEM:
	    if (fprintf(ofstream,pem_prolog)<0) {
                is_err = -1;
                break;
            }

            buf_len = node->len << 1;
            base_buf = (char*) malloc((size_t)buf_len);
	    memset(base_buf,0,buf_len);
            if (base64_encode(base_buf, &buf_len, node->data, 
                        (int) node->len) != 0) {
                is_err = -1;
                break;
            }
	    
	    n=strlen(base_buf);
	    for(i=0;i<n;i+=64) {
		fprintf(ofstream,"%.64s\n",&base_buf[i]);
	    }
           
	    if (fprintf(ofstream, pem_epilog)<0) {
                is_err = -1;
                break;
            }

            free(base_buf);
    }

    fclose(ofstream);

    if (is_err = -1)
        return 1;

    return 0;
}

/*
 * add the owner public key to x509 certificate
 */
int x509_add_pubkey(x509_raw *chain, rsa_context *pubkey)
{
    x509_node n_tmp, n_tmp2, *node;
    int ret;
        
    node = &chain->subpubkey;
    
    x509_init_node(&n_tmp);
    x509_init_node(&n_tmp2);

    /*
    *  RSAPublicKey ::= SEQUENCE {
    *      modulus           INTEGER,  -- n
    *      publicExponent    INTEGER   -- e
    *  }
    */
    if ((ret = asn1_add_mpi(&pubkey->N, ASN1_INTEGER, &n_tmp)) != 0)
        return ret;
    if ((ret = asn1_add_mpi(&pubkey->E, ASN1_INTEGER, &n_tmp)) != 0)
        return ret;
    if ((ret = asn1_append_tag(&n_tmp, ASN1_CONSTRUCTED | ASN1_SEQUENCE)) != 0)
        return ret;

    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    if ((ret = asn1_append_tag(&n_tmp, ASN1_BIT_STRING)) != 0)
       return ret;
    if ((ret = asn1_add_oid(&n_tmp2, OID_PKCS1_RSA, 9, 
                  ASN1_CONSTRUCTED | ASN1_SEQUENCE, ASN1_NULL, 
                  (unsigned char *)"", 0)) != 0)
        return ret;

    if ((ret = asn1_append_nodes(node, ASN1_CONSTRUCTED | ASN1_SEQUENCE, 2,
                   &n_tmp2, &n_tmp)) != 0)
       return ret;

    return 0;
}

/*
 *  RelativeDistinguishedName ::=
 *    SET OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 */
static int x509_add_name(x509_node *node, unsigned char *oid, 
        unsigned int oid_len, unsigned char *value)
{
    int ret;
    x509_node n_tmp;

    x509_init_node(&n_tmp);

    if (ret = asn1_add_oid(&n_tmp, oid, oid_len, 
                ASN1_CONSTRUCTED | ASN1_SEQUENCE, ASN1_PRINTABLE_STRING, 
                value, strlen(value)) != 0)
        return ret;

    if ((asn1_append_nodes(node, ASN1_CONSTRUCTED | ASN1_SET, 1, &n_tmp)) != 0)
        return ret;

    return 0;
}

/*
 * subject   Name
 */
int x509_create_subject(x509_raw *chain, unsigned char *names)
{
    unsigned char text[256], *text_sp, *sp;
    unsigned char oid[3] = OID_X520, tag[4], *tag_sp;
    int ret, is_tag = 1, is_ok = -1;
    x509_node *node;
        
    node = &chain->subject;
    tag_sp = tag;
    text_sp = text;

    for (sp = names; *sp != '\0'; ++sp) {

        /* filter tag */
        if (is_tag == 1) {

            if (tag_sp == &tag[3])
                return ERR_X509_VALUE_TO_LENGTH;

            /* is tag end? */
            if (*sp == '=') {
                is_tag = -1;
                ++sp; /* spring to "'" */
                *tag_sp = '\0';

                /* set text pointer to begin */
                text_sp = text;
            } else {
                /* tag hasn't ' '! */
                if (*sp != ' ') {
                    *tag_sp = *sp;
                    ++tag_sp;
                }
            }
        /* filter value */
        } else {

            if (text_sp == &text[255])
                return ERR_X509_VALUE_TO_LENGTH;

            /* is value at end? */
            if (*sp == '\'') {
                *text_sp = '\0';
                is_ok = 1;
                is_tag = 1;

                /* set tag poiner to begin */
                tag_sp = tag;
            } else {
                *text_sp = *sp;
                ++text_sp;
            }
        }

        /* add subject object */
        if (is_ok == 1) {
            if (tag[0] == 'C' and tag[1] == 'N') {
                oid[2] = X520_COMMON_NAME;
                if ((ret = x509_add_name(node, oid, 3, text)) != 0)
                    return ret;

            } else if (tag[0] == 'O' and tag[1] == '\0') {
                oid[2] = X520_ORGANIZATION;
                if ((ret = x509_add_name(node, oid, 3, text)) != 0)
                    return ret;

            } else if (tag[0] == 'O' and tag[1] == 'U') {
                oid[2] = X520_ORG_UNIT;
                if ((ret = x509_add_name(node, oid, 3, text)) != 0)
                    return ret;

            } else if (tag[0] == 'S' and tag[1] == 'T') {
                oid[2] = X520_STATE;
                if ((ret = x509_add_name(node, oid, 3, text)) != 0)
                    return ret;

            } else if (tag[0] == 'L' and tag[1] == '\0') {
                oid[2] = X520_LOCALITY;
                if ((ret = x509_add_name(node, oid, 3, text)) != 0)
                    return ret;

            } else if (tag[0] == 'R' and tag[1] == '\0') {
                if ((ret = x509_add_name(node, OID_PKCS9_EMAIL, 9, text)) 
                        != 0)
                    return ret;
            }
            is_ok = -1;
        }
    }

    if ((asn1_append_tag(node, ASN1_CONSTRUCTED | ASN1_SEQUENCE)) != 0)
        return ret;

    return 0; 
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
/* TODO: No handle GeneralizedTime! */
int x509_create_validity(x509_raw *chain, unsigned char *befor, 
        unsigned char *after)
{
    int ret;

    x509_node *node = &chain->validity;
    
    /* notBefore */
    if ((ret = asn1_add_date_utc(befor, node)) != 0)
        return ret;

    /* notAfter */
    if ((ret = asn1_add_date_utc(after, node)) != 0)
        return ret;

    if ((ret = asn1_append_tag(node, ASN1_CONSTRUCTED | ASN1_SEQUENCE)) != 0)
        return ret;

    return 0;
}

/*
 * Create a self signed certificate
 */
int x509_create_selfsign(x509_raw *chain, rsa_context *privkey)
{
    int ret, serial;
    unsigned char hash[20], *sign;
    size_t sign_len = (size_t) mpi_msb(&privkey->N) / 8;

    if (mpi_msb(&privkey->N) % 8 != 0)
        ++sign_len;
    
    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */
    if ((ret = asn1_add_int(2, &chain->version)) != 0)
        return ret;

    if ((ret = asn1_append_tag(&chain->version, ASN1_CONTEXT_SPECIFIC | 
                    ASN1_CONSTRUCTED)) != 0)
        return ret;


    /*
     *  CertificateSerialNumber  ::=  INTEGER
     */
    srand((unsigned int) time(NULL));
    serial = rand();
    if ((ret = asn1_add_int(serial, &chain->serial)) != 0)
        return ret;

    /*
     *  AlgorithmIdentifier  ::=  SEQUENCE  {
     *       algorithm               OBJECT IDENTIFIER,
     *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
     */
    if ((ret = asn1_add_oid(&chain->tbs_signalg, OID_PKCS1_RSA_SHA, 9, 
                  ASN1_CONSTRUCTED | ASN1_SEQUENCE, ASN1_NULL, "", 0)) != 0)
        return ret;


   /*
    * On self signed certificate are subject and issuer the same
    */
   chain->issuer = chain->subject;

   /*
    *  Create the tbs
    */
    if ((ret = asn1_append_nodes(&chain->tbs, ASN1_CONSTRUCTED | 
                    ASN1_SEQUENCE, 7, &chain->version, &chain->serial, 
                    &chain->tbs_signalg, &chain->issuer, &chain->validity, 
                    &chain->subject, &chain->subpubkey)) != 0)
        return ret;
 
    /* make hash */
    sha1(chain->tbs.data, chain->tbs.len, hash);

    /* create sign */
    sign = (unsigned char *) malloc(sign_len);
    if (sign == NULL)
        return ERR_X509_MEMORY_ALLOC_FAILED;

    if ((ret = rsa_pkcs1_sign(privkey, RSA_SHA1, hash, 20, sign, 
                    sign_len)) != 0)
        return ret;

    asn1_add_obj(sign, sign_len, ASN1_BIT_STRING, &chain->sign);

    free(sign);

    /*
     *  AlgorithmIdentifier  ::=  SEQUENCE  {
     *       algorithm               OBJECT IDENTIFIER,
     *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
     */
    if ((ret = asn1_add_oid(&chain->signalg, OID_PKCS1_RSA_SHA, 9, 
                  ASN1_CONSTRUCTED | ASN1_SEQUENCE, ASN1_NULL, "", 0)) != 0)
        return ret;

    /* finishing */
    if ((ret = asn1_append_nodes(&chain->raw, ASN1_CONSTRUCTED | 
                    ASN1_SEQUENCE, 3, &chain->tbs, &chain->signalg, 
                    &chain->sign)) != 0)
        return ret;

    return 0;
}

/*
 * Free memory
 */
void x509_free_raw(x509_raw *chain)
{
    x509_free_node(&chain->raw);
    x509_free_node(&chain->tbs);
    x509_free_node(&chain->version);
    x509_free_node(&chain->serial);
    x509_free_node(&chain->tbs_signalg);
    x509_free_node(&chain->issuer);
    x509_free_node(&chain->validity);
    if (chain->subject.data != chain->issuer.data)
        x509_free_node(&chain->subject);
    x509_free_node(&chain->subpubkey);
    x509_free_node(&chain->signalg);
    x509_free_node(&chain->sign);
}

void x509_init_raw(x509_raw *chain)
{
    memset((void *) chain, 0, sizeof(x509_raw));
}

