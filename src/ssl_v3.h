#ifndef _SSL_V3_H
#define _SSL_V3_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

#define ERR_SSL_INVALID_MAC                     0x0400
#define ERR_SSL_INVALID_RECORD                  0x0420
#define ERR_SSL_INVALID_MODULUS_SIZE            0x0440
#define ERR_SSL_UNKNOWN_CIPHER                  0x0460
#define ERR_SSL_NO_CIPHER_ACCEPTABLE            0x0480
#define ERR_SSL_CERTIFICATE_TOO_LARGE           0x04A0
#define ERR_SSL_CERTIFICATE_REQUIRED            0x04C0
#define ERR_SSL_PRIVATE_KEY_REQUIRED            0x04E0
#define ERR_SSL_CA_CHAIN_REQUIRED               0x0500
#define ERR_SSL_UNEXPECTED_MESSAGE              0x0520
#define ERR_SSL_FATAL_ALERT_MESSAGE             0x0540
#define ERR_SSL_PEER_VERIFY_FAILED              0x0560
#define ERR_SSL_PEER_CLOSE_NOTIFY               0x0580
#define ERR_SSL_BAD_HS_CLIENT_HELLO             0x05A0
#define ERR_SSL_BAD_HS_SERVER_HELLO             0x05C0
#define ERR_SSL_BAD_HS_CERTIFICATE              0x05E0
#define ERR_SSL_BAD_HS_CERTIFICATE_REQUEST      0x0600
#define ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE      0x0620
#define ERR_SSL_BAD_HS_SERVER_HELLO_DONE        0x0640
#define ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE      0x0660
#define ERR_SSL_BAD_HS_CERTIFICATE_VERIFY       0x0680
#define ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC       0x06A0
#define ERR_SSL_BAD_HS_FINISHED                 0x06C0

/*
 * Supported ciphersuites
 */
#define SSL3_RSA_RC4_128_MD5            4
#define SSL3_RSA_RC4_128_SHA            5
#define SSL3_RSA_DES_192_SHA           10
#define TLS1_RSA_AES_256_SHA           53

/*
 * TODO: Ephemeral Diffie-Hellman
 *
#define SSL3_EDH_RSA_DES_192_SHA       22
#define TLS1_EDH_RSA_AES_256_SHA       57
*/

/*
 * Various constants
 */
#define SSLV3_MAJOR_VERSION             3
#define SSLV3_MINOR_VERSION             0
#define TLS10_MINOR_VERSION             1
#define TLS11_MINOR_VERSION             2

#define SSL_MAX_RECORD_LEN          16384
#define SSL_COMPRESS_NULL               0
#define SSL_IS_CLIENT                   0
#define SSL_IS_SERVER                   1

#define SSL_VERIFY_NONE                 0
#define SSL_VERIFY_OPTIONAL             1
#define SSL_VERIFY_REQUIRED             2

/*
 * Message, alert and handshake types
 */
#define SSL_MSG_CHANGE_CIPHER_SPEC     20
#define SSL_MSG_ALERT                  21
#define SSL_MSG_HANDSHAKE              22
#define SSL_MSG_APPLICATION_DATA       23

#define SSL_ALERT_CLOSE_NOTIFY          0
#define SSL_ALERT_WARNING               1
#define SSL_ALERT_FATAL                 2

#define SSL_HS_HELLO_REQUEST            0
#define SSL_HS_CLIENT_HELLO             1
#define SSL_HS_SERVER_HELLO             2
#define SSL_HS_CERTIFICATE             11
#define SSL_HS_SERVER_KEY_EXCHANGE     12
#define SSL_HS_CERTIFICATE_REQUEST     13
#define SSL_HS_SERVER_HELLO_DONE       14
#define SSL_HS_CERTIFICATE_VERIFY      15
#define SSL_HS_CLIENT_KEY_EXCHANGE     16
#define SSL_HS_FINISHED                20

#include "sha1.h"
#include "md5.h"
#include "rsa.h"
#include "x509.h"

typedef struct
{
    /*
     * Highest version from client (to detect rollback attacks)
     */
    uchar max_client_ver[2];

    /*
     * Negotiated protocol version
     */
    uint major_version; /* always equal to SSLV3_MAJOR_VERSION */
    uint minor_version; /* either 0 (SSL v3.0) or 1 (TLS v1.0) */

    /*
     * Record layer -- incoming data
     */
    int read_fd;        /* descriptor for read operations   */

    uint  in_msgtype;   /* record header: message type      */
    uint  in_msglen;    /* record header: message length    */
    uint  in_prvlen;    /* previous message length          */
    uchar in_alert[2];  /* incoming alert level and descr.  */  

    uchar *in_ctr;      /* 64-bit incoming message counter  */
    uchar *in_hdr;      /* 5-byte record header (in_ctr+8)  */
    uchar *in_msg;      /* the message payload  (in_hdr+5)  */

    uint  left;         /* amount of appl. data not read    */

    /*
     * Record layer -- outgoing data
     */
    int write_fd;       /* descriptor for write operations  */

    uint  out_msgtype;  /* record header: message type      */
    uint  out_msglen;   /* record header: message length    */

    uchar *out_ctr;     /* 64-bit outgoing message counter  */
    uchar *out_hdr;     /* 5-byte record header (out_ctr+8) */
    uchar *out_msg;     /* the message payload  (out_hdr+5) */

    /*
     * PKI stuff
     */
    uint endpoint;              /* 0: client, 1: server   */
    rsa_context *own_key;       /* own RSA private key    */
    x509_cert *own_cert;        /* own X.509 certificate  */
    x509_cert *ca_chain;        /* own trusted CA chain   */
    x509_cert *peer_cert;       /* peer X.509 cert. chain */
    char *peer_cn;              /* expected peer CN       */
    uint client_auth;           /* flag for client auth.  */
    uint verify_mode;           /* verification mode      */
    uint verify_result;         /* verification result    */

    /*
     * Crypto stuff
     */
     md5_context hs_md5;        /*  MD5( Handshake msgs ) */
    sha1_context hs_sha1;       /* SHA1( Handshake msgs ) */
    uint hslen;                 /* handshake message len. */

    ulong (*rng_func)(void *);  /* RNG function           */
    void *rng_state;            /* RNG state              */
    uchar randbytes[64];        /* random bytes           */
    uchar premaster[48];        /* premaster secret       */
    uchar master[48];           /* master secret          */

    uint *cipherlist;           /* accepted ciphersuites  */
    uint cipher;                /* current chosen cipher  */
    uint minlen;                /* min. ciphertext len    */
    uint ctxlen;                /* cipher context length  */
    void *encrypt_ctx;          /* encryption context     */
    void *decrypt_ctx;          /* decryption context     */

    uint ivlen;                 /* IV length              */
    uchar iv_enc[16];           /* IV (encryption)        */
    uchar iv_dec[16];           /* IV (decryption)        */

    uint maclen;                /* MAC length             */
    uchar mac_enc[32];          /* MAC (encryption)       */
    uchar mac_dec[32];          /* MAC (decryption)       */
}
ssl_context;

/*
 * Internal functions (do not call directly)
 */
int ssl_read_record(  ssl_context *ssl, int do_crypt );
int ssl_write_record( ssl_context *ssl, int do_crypt );

int ssl_parse_certificate( ssl_context *ssl );
int ssl_write_certificate( ssl_context *ssl );

int ssl_parse_change_cipher_spec( ssl_context *ssl );
int ssl_write_change_cipher_spec( ssl_context *ssl );

int ssl_derive_keys( ssl_context *ssl );

int ssl_parse_finished( ssl_context *ssl );
int ssl_write_finished( ssl_context *ssl );

/*
 * Setup the list of allowed ciphers and the RNG context.
 * Also allocate memory for the input and output buffers;
 * returns 1 if allocation failed, or 0 if successful.
 */
int ssl_init( ssl_context *ssl, uint *cipherlist,
              ulong (*rng_func)(void *), void *rng_state );

/*
 * Setup the read and write file descriptors.
 */
int ssl_set_io_files( ssl_context *ssl, int read_fd, int write_fd );

/*
 * Setup own certificate and private key struct.
 */
int ssl_set_own_cert( ssl_context *ssl, x509_cert *own_cert,
                      rsa_context *own_key );

/*
 * Setup the CA cert chain used to verify peer cert and expected CN.
 */
int ssl_set_ca_chain( ssl_context *ssl, x509_cert *ca, char *cn );

/*
 * Perform an SSL handshake with the server; server_verify may be:
 *
 *  SSL_VERIFY_NONE: the server certificate is not checked
 *
 *  SSL_VERIFY_OPTIONAL: server certificate is checked, however the
 *                       handshake continues even if verification failed
 *                       (you may want to check ssl->verify_result after)
 *
 *  SSL_VERIFY_REQUIRED: server *must* present a valid certificate,
 *                       handshake is aborted if verification failed.
 *
 * This function returns 0 when successful, or an SSL error code.
 */
int ssl_client_start( ssl_context *ssl, int server_verify );

/*
 * Perform an SSL handshake with the client; client_verify may be:
 *
 *  SSL_VERIFY_NONE: no client certificates are asked
 *
 *  SSL_VERIFY_OPTIONAL: client certificate is checked, however the
 *                       handshake continues even if verification failed
 *                       (you may want to check ssl->verify_result after)
 *
 *  SSL_VERIFY_REQUIRED: client *must* present a valid certificate,
 *                       handshake is aborted if verification failed.
 *
 * This function returns 0 when successful, or an SSL error code.
 */
int ssl_server_start( ssl_context *ssl, int client_verify );

/*
 * Receive application data decrypted from the SSL layer.
 *
 * If "full" is zero, ssl_real behaves like read(): less
 * than *len bytes may be read. If full is non-zero, the
 * exact amount of data requested is read.
 */
int ssl_read( ssl_context *ssl, uchar *buf, uint *len, int full );

/*
 * Send application data to be encrypted by the SSL layer;
 * the peer will receive exactly len bytes from ssl_read()
 */
int ssl_write( ssl_context *ssl, uchar *buf, uint len );

/*
 * Close the SSL connection and cleanup/free all data.
 */
void ssl_close( ssl_context *ssl );

#ifdef __cplusplus
}
#endif

#endif /* ssl_v3.h */
