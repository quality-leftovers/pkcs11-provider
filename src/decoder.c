/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0

   PKCS#11 PEM based on TSS PEM in tpm2-openssl by Petr Gotthard
*/

#include "provider.h"
#include "decoder.h"
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include "encoder.gen.h"

struct p11prov_decoder_ctx {
    P11PROV_CTX *provctx;
    P11PROV_OBJ **objects;
    int num_objs;
};
typedef struct p11prov_decoder_ctx P11PROV_DECODER_CTX;

static OSSL_FUNC_decoder_newctx_fn p11prov_decoder_newctx;
static OSSL_FUNC_decoder_freectx_fn p11prov_decoder_freectx;

extern P11PROV_KEYPAIR_REF *d2i_P11PROV_KEYPAIR_REF(P11PROV_KEYPAIR_REF **a,
                                                    const unsigned char **in,
                                                    long len);

static void *p11prov_decoder_newctx(void *provctx)
{
    P11PROV_CTX *cprov;
    P11PROV_DECODER_CTX *dctx;
    cprov = provctx;
    dctx = OPENSSL_zalloc(sizeof(P11PROV_DECODER_CTX));
    if (dctx == NULL) return NULL;

    dctx->provctx = cprov;
    return dctx;
}

static void p11prov_decoder_freectx(void *inctx)
{
    P11PROV_DECODER_CTX *ctx = inctx;

    for (int i = 0; i < ctx->num_objs; i++) {
        p11prov_obj_free(ctx->objects[i]);
    }
    OPENSSL_free(ctx->objects);

    OPENSSL_clear_free(ctx, sizeof(P11PROV_DECODER_CTX));
}

#define OBJS_ALLOC_SIZE 1

/* [q-l][todo]: I have no idea, if the ctx is ever reused for decoding. Rework */
static CK_RV p11prov_decoder_ctx_store_obj(void *pctx, P11PROV_OBJ *obj)
{
    P11PROV_DECODER_CTX *ctx = pctx;

    P11PROV_debug("Adding object (handle:%lu)", p11prov_obj_get_handle(obj));

    if (p11prov_obj_get_class(obj) != CKO_PRIVATE_KEY) {
        P11PROV_raise(ctx->provctx, CKR_ARGUMENTS_BAD,
                      "Object must be private key");
        return CKR_ARGUMENTS_BAD;
    }
    if (ctx->num_objs > 0) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR,
                      "More than one matching object found");
        return CKR_GENERAL_ERROR;
    }

    if ((ctx->num_objs % OBJS_ALLOC_SIZE) == 0) {
        P11PROV_OBJ **tmp =
            OPENSSL_realloc(ctx->objects, (ctx->num_objs + OBJS_ALLOC_SIZE)
                                              * sizeof(P11PROV_OBJ *));
        if (tmp == NULL) {
            P11PROV_raise(ctx->provctx, CKR_HOST_MEMORY,
                          "Failed to allocate store objects");
            p11prov_obj_free(obj);
            return CKR_HOST_MEMORY;
        }
        ctx->objects = tmp;
    }
    ctx->objects[ctx->num_objs] = obj;
    ctx->num_objs += 1;

    return CKR_OK;
}

static CK_RV p11prov_decoder_load_key(P11PROV_DECODER_CTX *ctx,
                                      const char *inuri,
                                      OSSL_PASSPHRASE_CALLBACK *pw_cb,
                                      void *pw_cbarg, P11PROV_OBJ **obj)
{
    P11PROV_URI *parsed_uri = NULL;
    CK_RV ret = CKR_GENERAL_ERROR;
    P11PROV_SESSION *session;

    parsed_uri = p11prov_parse_uri(ctx->provctx, inuri);

    if (inuri == NULL) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to parse URI");
        goto done;
    }

    ret = p11prov_ctx_status(ctx->provctx);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx->provctx, ret, "Invalid context status");
    }

    /* Try to retrieve from cache */
    if (ctx->num_objs == 1) {
        /* [q-l][todo]: Does this even make sense? */
        P11PROV_OBJ *cached = ctx->objects[0];

        CK_ATTRIBUTE *cached_id = p11prov_obj_get_attr(cached, CKA_ID);
        if (cached_id == NULL) {
            P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR,
                          "Failed to get CKA_ID");
            ret = CKR_GENERAL_ERROR;
            goto done;
        }

        CK_ATTRIBUTE uri_id = p11prov_uri_get_id(parsed_uri);
        if (uri_id.type != CKA_ID) {
            P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR,
                          "URI must contain CKA_ID");
            ret = CKR_ARGUMENTS_BAD;
            goto done;
        }

        if ((cached_id->ulValueLen != uri_id.ulValueLen)
            || memcmp(uri_id.pValue, cached_id->pValue, cached_id->ulValueLen)
                   != 0) {
            P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR,
                          "Cached id mismatch");
            ret = CKR_ARGUMENTS_BAD;
            goto done;
        }

        goto success;
    }

    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    ret = p11prov_get_session(ctx->provctx, &slotid, NULL, parsed_uri,
                              CK_UNAVAILABLE_INFORMATION, pw_cb, pw_cbarg, true,
                              false, &session);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx->provctx, ret, "Failed to get session to load keys");
        goto done;
    }

    ret = p11prov_obj_find(ctx->provctx, session, slotid, parsed_uri,
                           p11prov_decoder_ctx_store_obj, ctx);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx->provctx, ret, "Failed to find matching object");
        goto done;
    }

    if (ctx->num_objs != 1) {
        ret = CKR_ARGUMENTS_BAD;
        P11PROV_raise(ctx->provctx, ret, "No matching object stored");
        goto done;
    }

success: /* Matching object was found or already cached */
    ret = CKR_OK;
    *obj = ctx->objects[0];

done:
    p11prov_uri_free(parsed_uri);

    P11PROV_debug("Done (result:%d)", ret);
    return ret;
}

static int
p11prov_decoder_decode_p11key(CK_KEY_TYPE desired_key_type, void *inctx,
                              OSSL_CORE_BIO *cin, int selection,
                              OSSL_CALLBACK *object_cb, void *object_cbarg,
                              OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    P11PROV_DECODER_CTX *ctx = inctx;
    P11PROV_KEYPAIR_REF *key = NULL;
    BIO *bin;
    int ret = 0;
    const char *uri = NULL;

    P11PROV_debug("P11 KEY DECODER DECODE (selection:0x%x)", selection);
    if ((bin = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cin))
        == NULL) {
        P11PROV_debug("P11 KEY DECODER BIO_new_from_core_bio failed");
        goto done;
    }

    const char *data_type = NULL;
    switch (desired_key_type) {
    case CKK_RSA:
        data_type = P11PROV_NAME_RSA;
        break;
    case CKK_EC:
        data_type = P11PROV_NAME_EC;
        break;
    default:
        ret = 0;
        P11PROV_raise(ctx->provctx, CKR_ARGUMENTS_BAD, "Unsupported key type");
        goto done;
    }

    const unsigned char *der;
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

    if (key->key_type == NULL) {
        P11PROV_raise(ctx->provctx, CKR_ARGUMENTS_BAD,
                      "Field key_type is NULL");
        goto done;
    }
    CK_KEY_TYPE key_type = (CK_KEY_TYPE)ASN1_INTEGER_get(key->key_type);
    if (key_type != desired_key_type) {
        P11PROV_debug(
            "P11 KEY DECODER key type mismatch (desired:%lu, actual:%lu)",
            desired_key_type, key_type);
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

    uri = (const char *)ASN1_STRING_get0_data(key->uri);
    if (uri == NULL) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to get URI");
        goto done;
    }

    P11PROV_OBJ *obj = NULL;
    if (p11prov_decoder_load_key(ctx, uri, pw_cb, pw_cbarg, &obj) == CKR_OK) {
        P11PROV_debug("P11 KEY DECODER p11prov_decoder_load_key OK");

        void *key_reference = NULL;
        size_t key_reference_sz = 0;
        p11prov_obj_to_store_reference(obj, &key_reference, &key_reference_sz);

        int object_type = OSSL_OBJECT_PKEY;
        OSSL_PARAM params[4];
        params[0] =
            OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_TYPE, (char *)data_type, 0);
        /* The address of the key becomes the octet string */
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_REFERENCE, key_reference, key_reference_sz);
        params[3] = OSSL_PARAM_construct_end();
        object_cb(params, object_cbarg);
    } else {
        P11PROV_debug("P11 KEY DECODER p11prov_decoder_load_key failed");
    }

done:
    P11PROV_KEYPAIR_REF_free(key);
    BIO_free(bin);
    P11PROV_debug("P11 KEY DECODER RESULT=%d", ret);
    return ret;
}

static int p11prov_der_decoder_p11_rsa_decode(
    void *inctx, OSSL_CORE_BIO *cin, int selection, OSSL_CALLBACK *object_cb,
    void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    return p11prov_decoder_decode_p11key(CKK_RSA, inctx, cin, selection,
                                         object_cb, object_cbarg, pw_cb,
                                         pw_cbarg);
}

const OSSL_DISPATCH p11prov_der_decoder_p11_rsa_functions[] = {
    DISPATCH_BASE_DECODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_DECODER_ELEM(FREECTX, freectx),
    DISPATCH_DECODER_ELEM(DECODE, der, p11, rsa, decode),
    { 0, NULL }
};

static int p11prov_der_decoder_p11_ec_decode(
    void *inctx, OSSL_CORE_BIO *cin, int selection, OSSL_CALLBACK *object_cb,
    void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    return p11prov_decoder_decode_p11key(CKK_EC, inctx, cin, selection,
                                         object_cb, object_cbarg, pw_cb,
                                         pw_cbarg);
}

const OSSL_DISPATCH p11prov_der_decoder_p11_ec_functions[] = {
    DISPATCH_BASE_DECODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_DECODER_ELEM(FREECTX, freectx),
    DISPATCH_DECODER_ELEM(DECODE, der, p11, ec, decode),
    { 0, NULL }
};

static int p11prov_pem_decoder_p11_der_decode(
    void *inctx, OSSL_CORE_BIO *cin, int selection, OSSL_CALLBACK *object_cb,
    void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
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

    if ((bin = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cin))
        == NULL) {
        P11PROV_debug("BIO_new_from_core_bio failed");
        return 0;
    }
    P11PROV_debug("DER DECODER PEM_read_pio (fpos:%u)", BIO_tell(bin));

    if (PEM_read_bio(bin, &pem_name, &pem_header, &der_data, &der_len) > 0
        && strcmp(pem_name, P11PROV_PRIVKEY_PEM_NAME) == 0) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                      der_data, der_len);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_STRUCTURE, (char *)"P11", 0);
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
