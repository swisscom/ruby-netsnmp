#include <ruby.h>

#define USM_LENGTH_EXPANDED_PASSPHRASE	(1024 * 1024)   /* 1Meg. */
#define USM_LENGTH_KU_HASHBLOCK		64

static VALUE mNETSNMP;
static VALUE cNETSNMP_Sec_Params;

static VALUE NETSNMP_expand_passphrase(VALUE self, VALUE password)
{
  char *P;
  size_t P_len;
  int nbytes = USM_LENGTH_EXPANDED_PASSPHRASE;
  u_int           pindex = 0;
  u_char          buf[USM_LENGTH_EXPANDED_PASSPHRASE], *bufp;

  StringValue(password);
  P = RSTRING_PTR(password);
  P_len = RSTRING_LEN(password);

  bufp = buf;
  while (nbytes > 0) {
    *bufp++ = P[pindex++ % P_len];
    // if (!EVP_DigestUpdate(ctx, buf, USM_LENGTH_KU_HASHBLOCK))
    //   ossl_raise(eDigestError, "EVP_DigestUpdate");

    nbytes--;
  }

  // if (!EVP_DigestFinal_ex(ctx, &Ku, &kulen))
  //   ossl_raise(eDigestError, "EVP_DigestFinal_ex");

  // memset(buf, 0, sizeof(buf));

  // TODO: trim to 16 bytes if auth protocol is md5

  return rb_usascii_str_new((const char *) buf, USM_LENGTH_EXPANDED_PASSPHRASE);
}

void Init_netsnmp_ext( void )
{
    mNETSNMP = rb_define_module("NETSNMP");
    cNETSNMP_Sec_Params = rb_define_class_under(mNETSNMP, "SecurityParameters", rb_cObject);
    // rb_define_method(cNETSNMP_Sec_Params, "passkey", NETSNMP_passkey, 1);
    rb_define_method(cNETSNMP_Sec_Params, "expand_passphrase", NETSNMP_expand_passphrase, 1);
}