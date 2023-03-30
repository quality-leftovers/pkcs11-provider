/* TBD: derived from tpm2-provider-decoder-*.c
 * Based on the work in tpm2-openssl by Petr Gotthard
 *  */

#include "provider.h"
#include "decoder.h"
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/store.h>
#include "encoder.gen.h"

struct p11prov_decoder_ctx {
    P11PROV_CTX *provctx;
};
typedef struct p11prov_decoder_ctx P11PROV_DECODER_CTX;

static OSSL_FUNC_decoder_newctx_fn p11prov_decoder_newctx;
static OSSL_FUNC_decoder_freectx_fn p11prov_decoder_freectx;

extern P11PROV_KEYPAIR_REF *d2i_P11PROV_KEYPAIR_REF(P11PROV_KEYPAIR_REF **a,
                                                    const unsigned char **in,
                                                    long len);

static void * p11prov_decoder_newctx(void *provctx)
{
    P11PROV_CTX *cprov;
    P11PROV_DECODER_CTX *dctx;
    cprov = provctx;
    dctx = OPENSSL_zalloc(sizeof(P11PROV_DECODER_CTX));
    //P11PROV_debug("DECODER NEWCTX (%p)", dctx);
    if (dctx == NULL)
        return NULL;

    dctx->provctx = cprov;
    return dctx;
}

static void p11prov_decoder_freectx(void *ctx)
{
    P11PROV_DECODER_CTX *dctx;
    dctx = ctx;
    //P11PROV_debug("DECODER CTX FREE (%p)", dctx);
    OPENSSL_clear_free(dctx, sizeof(P11PROV_DECODER_CTX));
}

static int p11prov_der_decoder_p11_rsa_decode(void *inctx, OSSL_CORE_BIO *cin, int selection,
                        OSSL_CALLBACK *object_cb, void *object_cbarg,
                        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    P11PROV_DECODER_CTX *ctx = inctx;
    int ret;
    P11PROV_KEYPAIR_REF* key = NULL;
    BIO* bin;

    P11PROV_debug("P11 KEY DECODER DECODE (selection:0x%x)", selection);
    if ((bin = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cin)) == NULL) {
        P11PROV_debug("P11 KEY DECODER BIO_new_from_core_bio failed");
        return 0;
    }

    const unsigned char* der;
    long der_len = BIO_get_mem_data(bin, &der);
    if (der_len <= 0) {
        P11PROV_debug("P11 KEY DECODER BIO_get_mem_data failed");
        ret = 1;
        goto done;
    }
    if ((key = d2i_P11PROV_KEYPAIR_REF(NULL, &der, der_len)) == NULL) {
        P11PROV_debug("P11 KEY DECODER d2i_P11PROV_KEYPAIR_REF failed");
        ret = 1;
        goto done;
    }

    char oid_txt[64];
    if (OBJ_obj2txt(oid_txt, sizeof(oid_txt), key->type, 1) > 0) {
       P11PROV_debug("P11 KEY DECODER got OID %s", oid_txt);
    } else {
        P11PROV_debug("P11 KEY DECODER OBJ_obj2txt failed");
        goto done;
    }

    const char* uri = (const char*)ASN1_STRING_get0_data(key->uri);
    P11PROV_debug("P11 KEY DECODER got uri %s", uri);

    ret = 0;

    /* Obviously this will not work, but we can check if the key is dispatched to keymgmt :) */
    void* dummy_key_ref = NULL;
    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)"RSA", 0);
    /* The address of the key becomes the octet string */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &dummy_key_ref, sizeof(dummy_key_ref));
    params[3] = OSSL_PARAM_construct_end();
    object_cb(params, object_cbarg);

    P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "NOTIMPLEMENTED! How to continue?");

    ret = 1;
    goto done;

done:
    P11PROV_KEYPAIR_REF_free(key);
    BIO_free(bin);
    P11PROV_debug("P11 KEY DECODER RESULT=%d", ret);
    return ret;
}

const OSSL_DISPATCH p11prov_der_decoder_p11_rsa_functions[] = {
    DISPATCH_BASE_DECODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_DECODER_ELEM(FREECTX, freectx),
    DISPATCH_DECODER_ELEM(DECODE, der, p11, rsa, decode),
    { 0, NULL }
};

static int p11prov_pem_decoder_p11_der_decode(void *inctx, OSSL_CORE_BIO *cin, int selection,
                        OSSL_CALLBACK *object_cb, void *object_cbarg,
                        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{

    BIO *bin;
    char *pem_name;
    char *pem_header;
    unsigned char *der_data;
    long der_len;
    OSSL_PARAM params[3];
    int ret;
    P11PROV_DECODER_CTX *ctx = inctx;

    P11PROV_debug("DER DECODER DECODE (selection:0x%x)", selection);

    if ((bin = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cin)) == NULL) {
        P11PROV_debug("BIO_new_from_core_bio failed");
        return 0;
    }
    P11PROV_debug("DER DECODER PEM_read_pio (fpos:%u)", BIO_tell(bin));

    if (PEM_read_bio(bin, &pem_name, &pem_header, &der_data, &der_len) > 0
            && strcmp(pem_name, P11PROV_PRIVKEY_PEM_NAME) == 0) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, der_data, der_len);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE, (char*)"P11", 0);
        params[2] = OSSL_PARAM_construct_end();
        ret = object_cb(params, object_cbarg);
    } else {
        /* We return "empty handed". This is not an error. */
        ret = 1;
    }

    OPENSSL_free(pem_name);
    OPENSSL_free(pem_header);
    OPENSSL_free(der_data);
    BIO_free(bin);

    P11PROV_debug("DER DECODER RESULT=%d", ret);
    return ret;
}


const OSSL_DISPATCH p11prov_pem_decoder_p11_der_functions[] = {
    DISPATCH_BASE_DECODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_DECODER_ELEM(FREECTX, freectx),
    DISPATCH_DECODER_ELEM(DECODE, pem, p11, der, decode),
    { 0, NULL }
};
