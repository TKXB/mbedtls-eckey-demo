#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mbedtls/sha256.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#define mbedtls_free       free
#define mbedtls_printf          printf

static void print_hex(const char *title, const unsigned char buf[], size_t len)
{
    printf("%s: ", title);

    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);

    printf("\r\n");
}

static int myrand( void *rng_state, unsigned char *output, size_t len )
{
    size_t use_len;
    int rnd;

    if( rng_state != NULL )
        rng_state  = NULL;

    while( len > 0 )
    {
        use_len = len;
        if( use_len > sizeof(int) )
            use_len = sizeof(int);

        rnd = rand();
        memcpy( output, &rnd, use_len );
        output += use_len;
        len -= use_len;
    }

    return( 0 );
}

void ecp_clear_precomputed( mbedtls_ecp_group *grp )
{
    if( grp->T != NULL )
    {
        size_t i;
        for( i = 0; i < grp->T_size; i++ )
            mbedtls_ecp_point_free( &grp->T[i] );
        mbedtls_free( grp->T );
    }
    grp->T = NULL;
    grp->T_size = 0;
}

static int write_private_key_pem( mbedtls_pk_context *key, const char *output_file )
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);
        if( ( ret = mbedtls_pk_write_key_pem( key, output_buf, 16000 ) ) != 0 )
            return( ret );

        len = strlen( (char *) output_buf );

    if( ( f = fopen( output_file, "wb" ) ) == NULL )
        return( -1 );

    if( fwrite( c, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

static int write_public_key_pem( mbedtls_pk_context *key, const char *output_file )
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);

    if( ( ret = mbedtls_pk_write_pubkey_pem( key, output_buf, 16000 ) ) != 0 )
        return( ret );

    len = strlen( (char *) output_buf );


    if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( c, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

int main() {
    unsigned char output[32];
    static const char hello_str[] = "Hello, world!";
    static const unsigned char *hello_buffer = (const unsigned char *) hello_str;
    static const size_t hello_len = sizeof hello_str - 1;

    mbedtls_sha256_context mbedtlsSha256Context;
    mbedtls_sha256_init(&mbedtlsSha256Context);
    mbedtls_sha256_starts(&mbedtlsSha256Context, 0);
    mbedtls_sha256_update(&mbedtlsSha256Context, hello_buffer, hello_len);
    mbedtls_sha256_finish(&mbedtlsSha256Context, output);

    print_hex("sha256", output, sizeof(output));
    mbedtls_sha256_free(&mbedtlsSha256Context);

//chacha20 demo
    static const char message[] = "free software";
    static const unsigned char * message_buffer = (const unsigned char *) message;
    static const size_t message_len = sizeof message -1;
    const unsigned char key[32];
    const unsigned char nonce[12];
    unsigned char output_chacha20_enc[32];
    unsigned char output_chacha20_enc2[32];
    unsigned char output_chacha20_dec[32];
    unsigned char output_chacha20_dec2[32];
    uint32_t counter;
    memset(key, 'A', 32);
    memset(nonce, 1, 12);
    mbedtls_chacha20_context mbedtlsChacha20Context;
    mbedtls_chacha20_init(&mbedtlsChacha20Context);
    mbedtls_chacha20_setkey(&mbedtlsChacha20Context, key);
    mbedtls_chacha20_starts(&mbedtlsChacha20Context, &nonce, counter);
    mbedtls_chacha20_update(&mbedtlsChacha20Context, hello_len, hello_buffer, output_chacha20_enc);
    mbedtls_chacha20_update(&mbedtlsChacha20Context, message_len, message_buffer, output_chacha20_enc2);
    print_hex("chacha20_encryption", output_chacha20_enc, sizeof(output_chacha20_enc));

    mbedtls_chacha20_starts(&mbedtlsChacha20Context, &nonce, counter);
    mbedtls_chacha20_update(&mbedtlsChacha20Context, hello_len, output_chacha20_enc, output_chacha20_dec);
    mbedtls_chacha20_update(&mbedtlsChacha20Context, message_len, output_chacha20_enc2, output_chacha20_dec2);
    printf("chacha20 %s,%s", output_chacha20_dec, output_chacha20_dec2);
    mbedtls_chacha20_free(&mbedtlsChacha20Context);

    //ECC key demo
    int ret;
    mbedtls_pk_context mbedtlsPkContext;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const mbedtls_ecp_curve_info *curve_info;

    //initialization
    mbedtls_pk_init(&mbedtlsPkContext);
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init(&entropy);
    const char *pers = "gen_key";
    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,(const unsigned char *) pers,
                           strlen( pers ) );
    //use curve SECP256R1
    curve_info = mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256R1);

    //generate ECC key pair
    ret = mbedtls_pk_setup(&mbedtlsPkContext, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    ret = mbedtls_ecp_gen_key(curve_info->grp_id, mbedtls_pk_ec(mbedtlsPkContext), mbedtls_ctr_drbg_random, &ctr_drbg);
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_ecp_gen_key returned -0x%04x", -ret );
    }

    //print key pair
    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec( mbedtlsPkContext );
    mbedtls_printf( "curve: %s\n",
                    mbedtls_ecp_curve_info_from_grp_id( ecp->grp.id )->name );
    mbedtls_mpi_write_file( "X_Q:   ", &ecp->Q.X, 16, NULL );
    mbedtls_mpi_write_file( "Y_Q:   ", &ecp->Q.Y, 16, NULL );
    mbedtls_mpi_write_file( "D:     ", &ecp->d  , 16, NULL );

    //write key pair to file using pem format
    write_public_key_pem(&mbedtlsPkContext, "publickey.txt");
    write_private_key_pem(&mbedtlsPkContext, "privatekey.txt");

    //load key
    mbedtls_pk_context pk;
    mbedtls_pk_init( &pk );
    mbedtls_pk_parse_keyfile( &pk, "privatekey.txt", NULL );
    mbedtls_pk_parse_public_keyfile( &pk, "publickey.txt" );

    //ecdsa
    mbedtls_ecdsa_context mbedtlsEcdsaContext;
    size_t sig_len;
    unsigned char tmp[200];
    unsigned char buf[64];
    memset(buf, 0x2A, sizeof(buf));
    strcpy((char *)buf, "hello world"); //just fill with something other than 0x2A
    mbedtls_ecdsa_init(&mbedtlsEcdsaContext);
    mbedtls_ecdsa_from_keypair(&mbedtlsEcdsaContext, mbedtls_pk_ec(mbedtlsPkContext));

    int ret_write_sign = mbedtls_ecdsa_write_signature(&mbedtlsEcdsaContext, MBEDTLS_MD_SHA256, buf, curve_info->bit_size, tmp, &sig_len, myrand, NULL);
    ecp_clear_precomputed( &mbedtlsEcdsaContext.grp );
    int ret_verify = mbedtls_ecdsa_read_signature(&mbedtlsEcdsaContext, buf, curve_info->bit_size, tmp, sig_len);
    printf("ret_verify = %d\n", ret_verify);
    return 0;
}