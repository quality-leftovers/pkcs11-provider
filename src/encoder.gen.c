/* DO NOT EDIT, autogenerated from encoder.c.pre */
/* Modify encoder.c.pre then run make generate-code */

#include "provider.h"
#include "encoder.gen.h"

P11PROV_RSA_PUBKEY
*d2i_P11PROV_RSA_PUBKEY(P11PROV_RSA_PUBKEY **a, const unsigned char **in,
                        long len)
{
    return (P11PROV_RSA_PUBKEY *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
                                               (P11PROV_RSA_PUBKEY_it()));
}
int i2d_P11PROV_RSA_PUBKEY(const P11PROV_RSA_PUBKEY *a, unsigned char **out)
{
    return ASN1_item_i2d((const ASN1_VALUE *)a, out, (P11PROV_RSA_PUBKEY_it()));
}
P11PROV_RSA_PUBKEY
*P11PROV_RSA_PUBKEY_new(void)
{
    return (P11PROV_RSA_PUBKEY *)ASN1_item_new((P11PROV_RSA_PUBKEY_it()));
}
void P11PROV_RSA_PUBKEY_free(P11PROV_RSA_PUBKEY *a)
{
    ASN1_item_free((ASN1_VALUE *)a, (P11PROV_RSA_PUBKEY_it()));
}

static const ASN1_TEMPLATE P11PROV_RSA_PUBKEY_seq_tt[] = {

    { (0), (0), __builtin_offsetof(P11PROV_RSA_PUBKEY, n), "n",
      (ASN1_INTEGER_it) },

    { (0), (0), __builtin_offsetof(P11PROV_RSA_PUBKEY, e), "e",
      (ASN1_INTEGER_it) },
};
const ASN1_ITEM *P11PROV_RSA_PUBKEY_it(void)
{
    static const ASN1_ITEM local_it = { 0x1,
                                        16,
                                        P11PROV_RSA_PUBKEY_seq_tt,
                                        sizeof(P11PROV_RSA_PUBKEY_seq_tt)
                                            / sizeof(ASN1_TEMPLATE),
                                        ((void *)0),
                                        sizeof(P11PROV_RSA_PUBKEY),
                                        "P11PROV_RSA_PUBKEY" };
    return &local_it;
}

int PEM_write_bio_P11PROV_RSA_PUBKEY(BIO *out, const P11PROV_RSA_PUBKEY *x)
{
    return PEM_ASN1_write_bio((i2d_of_void *)i2d_P11PROV_RSA_PUBKEY,
                              "RSA PUBLIC KEY", out, x, ((void *)0),
                              ((void *)0), 0, ((void *)0), ((void *)0));
}

P11PROV_KEYPAIR_REF
*d2i_P11PROV_KEYPAIR_REF(P11PROV_KEYPAIR_REF **a, const unsigned char **in,
                         long len)
{
    return (P11PROV_KEYPAIR_REF *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
                                                (P11PROV_KEYPAIR_REF_it()));
}
int i2d_P11PROV_KEYPAIR_REF(const P11PROV_KEYPAIR_REF *a, unsigned char **out)
{
    return ASN1_item_i2d((const ASN1_VALUE *)a, out,
                         (P11PROV_KEYPAIR_REF_it()));
}
P11PROV_KEYPAIR_REF
*P11PROV_KEYPAIR_REF_new(void)
{
    return (P11PROV_KEYPAIR_REF *)ASN1_item_new((P11PROV_KEYPAIR_REF_it()));
}
void P11PROV_KEYPAIR_REF_free(P11PROV_KEYPAIR_REF *a)
{
    ASN1_item_free((ASN1_VALUE *)a, (P11PROV_KEYPAIR_REF_it()));
}
static const ASN1_TEMPLATE P11PROV_KEYPAIR_REF_seq_tt[] = {

    { (0), (0), __builtin_offsetof(P11PROV_KEYPAIR_REF, type), "type",
      (ASN1_OBJECT_it) },

    { (0), (0), __builtin_offsetof(P11PROV_KEYPAIR_REF, key_type), "key_type",
      (ASN1_INTEGER_it) },

    { (0), (0), __builtin_offsetof(P11PROV_KEYPAIR_REF, uri), "uri",
      (ASN1_PRINTABLESTRING_it) },
};
const ASN1_ITEM *P11PROV_KEYPAIR_REF_it(void)
{
    static const ASN1_ITEM local_it = { 0x1,
                                        16,
                                        P11PROV_KEYPAIR_REF_seq_tt,
                                        sizeof(P11PROV_KEYPAIR_REF_seq_tt)
                                            / sizeof(ASN1_TEMPLATE),
                                        ((void *)0),
                                        sizeof(P11PROV_KEYPAIR_REF),
                                        "P11PROV_KEYPAIR_REF" };
    return &local_it;
}

int PEM_write_bio_P11PROV_KEYPAIR_REF(BIO *out, const P11PROV_KEYPAIR_REF *x)
{
    return PEM_ASN1_write_bio((i2d_of_void *)i2d_P11PROV_KEYPAIR_REF,
                              P11PROV_PRIVKEY_PEM_NAME, out, x, ((void *)0),
                              ((void *)0), 0, ((void *)0), ((void *)0));
}

P11PROV_KEYPAIR_REF
*PEM_read_bio_P11PROV_KEYPAIR_REF(BIO *bp, P11PROV_KEYPAIR_REF **x,
                                  pem_password_cb *cb, void *u)
{
    return PEM_ASN1_read_bio((d2i_of_void *)d2i_P11PROV_KEYPAIR_REF,
                             P11PROV_PRIVKEY_PEM_NAME, bp, (void **)x, cb, u);
}
