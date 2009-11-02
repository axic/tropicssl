#ifndef _SSL_V3_H
#define _SSL_V3_H

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
#define ERR_SSL_CERTIFICATE_TOO_LARGE           0x0480
#define ERR_SSL_CERTIFICATE_REQUIRED            0x04A0
#define ERR_SSL_PRIVATE_KEY_REQUIRED            0x04C0
#define ERR_SSL_CA_CHAIN_REQUIRED               0x04E0
#define ERR_SSL_UNEXPECTED_MESSAGE              0x0500
#define ERR_SSL_FATAL_ALERT_MESSAGE             0x0520
#define ERR_SSL_PEER_VERIFY_FAILED              0x0540
#define ERR_SSL_PEER_CLOSE_NOTIFY               0x0560
#define ERR_SSL_BAD_HS_CLIENT_HELLO             0x0580
#define ERR_SSL_BAD_HS_SERVER_HELLO             0x05A0
#define ERR_SSL_BAD_HS_CERTIFICATE              0x05C0
#define ERR_SSL_BAD_HS_CERTIFICATE_REQUEST      0x05E0
#define ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE      0x0600
#define ERR_SSL_BAD_HS_SERVER_HELLO_DONE        0x0620
#define ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE      0x0640
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
     * Negotiated protocol version
     */
    uint major_version;
    uint minor_version;

    /*
     * Session ID, and pointer to session table (server only).
     */
    uint sidlen;
    uchar sid[64];
    void *sidtbl;

    /*
     * Record layer -- incoming data
     */
    int read_fd;

    uint in_msgtype;
    uint in_msglen;
    uint in_prvlen;

    uchar *in_ctr; /* msg counter */
    uchar *in_hdr; /* in_ctr + 8  */
    uchar *in_msg; /* in_hdr + 5  */

    uint left;

    /*
     * Record layer -- outgoing data
     */
    int write_fd;

    uint out_msgtype;
    uint out_msglen;

    uchar *out_ctr; /* msg counter */
    uchar *out_hdr; /* out_ctr + 8 */
    uchar *out_msg; /* out_hdr + 5 */

    /*
     * Incoming alert messages from peer
     * (byte 0: level, byte 1: description)
     */
    uchar in_alert[2];

    /*
     * MD5 and SHA1 hashes of all Handshake messages so far,
     * and length of current handshake message (multiple HS
     * messages may be contained in a single record).
     */
     md5_context  md5_handshake;
    sha1_context sha1_handshake;
    uint hslen;

    /*
     * Flag for client authentication.
     */
    uint client_auth;

    /*
     * Own RSA key and X.509 certificate.
     */
    rsa_context *own_key;
    x509_cert *own_cert;

    /*
     * Trusted CA chain, expected peer CN and verify mode.
     */
    x509_cert *ca_chain;
    char *peer_cn;
    uint verify_mode;

    /*
     * Cert. chain from peer and result of x509_verify_cert.
     */
    x509_cert *peer_cert;
    uint verify_result;

    /*
     * RNG used to generate the premaster secret
     */
    ulong (*rng_func)(void *);
    void *rng_state;

    /*
     * premaster + random bytes -> master -> key block
     */
    uchar randbytes[64];
    uchar premaster[48];
    uchar master[48];

    /*
     * Encryption flag, operation mode and minimum ciphertext len.
     */
    uint do_crypt;
    uint endpoint;
    uint minlen;

    /*
     * Accepted ciphersuites and chosen cipher.
     */
    uint *cipherlist, cipher;

    /*
     * Cipher encrypt/decrypt context & IVs, MAC secrets.
     */
    uint ctxlen;
    void *encrypt_ctx;
    void *decrypt_ctx;

    uint ivlen;
    uchar iv_enc[16];
    uchar iv_dec[16];

    uint maclen;
    uchar mac_enc[32];
    uchar mac_dec[32];
}
ssl_context;

/*
 * Internal functions (do not call directly)
 */
int ssl_read_record(  ssl_context *ssl );
int ssl_write_record( ssl_context *ssl );

int ssl_parse_certificate( ssl_context *ssl );
int ssl_write_certificate( ssl_context *ssl );

int ssl_parse_change_cipher_spec( ssl_context *ssl );
int ssl_write_change_cipher_spec( ssl_context *ssl );

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
 * Setup own certificate and private key struct, returns 0.
 */
int ssl_set_owncert( ssl_context *ssl, x509_cert *own_cert,
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
 * Receive application data decrypted from the SSL layer.
 * If "full" is not null, exactly *len bytes will be read;
 * otherwise the result of the read (stored in *len) may
 * be lesser than the requested size.
 *
 * In both cases, this function will block until data is
 * received at the record layer.
 */
int ssl_read( ssl_context *ssl, uchar *buf, uint *len, int full );

/*
 * Send application data to be encrypted by the SSL layer;
 * peer will receive exactly len bytes.
 */
int ssl_write( ssl_context *ssl, uchar *buf, uint len );

/*
 * Close the SSL connection. The context can be reused
 * afterwards (no need to call ssl_init again).
 */
void ssl_close( ssl_context *ssl );

/*
 * Cleanup the secrets and free all data; context cannot be used
 * anymore without calling ssl_init() first.
 */
void ssl_free( ssl_context *ssl );

#endif /* ssl_v3.h */
