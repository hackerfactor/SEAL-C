/************************************************
 SEAL: implemented in C
 See LICENSE

 Processing inline public key settings.
  pk=     :: a public key (also refered to as 'p' when in the dns entry in non inline format)
  pka=    :: algorithim used to generate the pkd
  pkd=    :: digest of the public key

  pk is set in the order of precedence of commandline > dnsfile > dns
 ************************************************/
// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

// for OpenSSL
#include <openssl/evp.h>

#include "seal-parse.hpp"
#include "sign.hpp"

/********************************************************
 SealGetPublicKey(): Get the public key for inline signing
 and set it in the pk field.
 ********************************************************/
sealfield *	SealGetPublicKey	(sealfield *Args)
{
  EVP_PKEY *keypair = NULL;
  // Nothing to do if not inline format, or pk is already defined via command line parameter
  if(!SealSearch(Args,"inline") || SealGetText(Args, "pk")) {return Args; }

  keypair = SealLoadPrivateKey(Args);
  Args = SealGenerateKeyPublic(Args, keypair);
  if(!SealSearch(Args, "@pubder"))
  {
    printf("ERROR: Could not generate public key for inline signature\n");
    exit(0x80);
  }
  Args = SealCopy(Args, "pk", "@pubder");
  return Args;
} /*SealGetPublicKey()*/

/********************************************************
 SealInlineAuthenticate(): For an inline signature, verify that the
 public key digest (pkd) matches the public key (pk).
 ********************************************************/
sealfield * SealInlineAuthenticate    (sealfield *Args){
  char *pk, *pkd, *pka;
  const EVP_MD* (*mdf)(void);
  char *pkdCalc;
  sealfield *pk_bin_vf, *pkd_calc_vf;

  // Get parameters from Args
  pk = SealGetText(Args, "pk");
  pkd = SealGetText(Args, "pkd");
  pka = SealGetText(Args, "pka");

  // If any are missing, we can't verify.
  if (!pk || !pkd || !pka) {
    // This is not an error, just means it's not an inline signature
    // or the DNS record is missing pkd/pka.
    return Args;
  }

  // Determine digest algorithm from pka
  mdf = SealGetMdfFromString(pka);
  if (!mdf) {
    Args = SealSetText(Args, "@error", "Unsupported public key digest algorithm (pka)");
    return Args;
  }

  // The public key 'pk' is base64 encoded. We need its binary form.
  Args = SealSetText(Args, "@pkbin", pk);
  pk_bin_vf = SealSearch(Args, "@pkbin");
  SealBase64Decode(pk_bin_vf);

  if (SealGetSize(Args, "@pkbin") <= 0) {
    Args = SealSetText(Args, "@error", "Failed to base64 decode public key (pk)");
    SealDel(Args, "@pkbin");
    return Args;
  }

  // Calculate digest of the public key
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  EVP_DigestInit(ctx, mdf());
  EVP_DigestUpdate(ctx, pk_bin_vf->Value, pk_bin_vf->ValueLen);

  unsigned int mdsize = EVP_MD_size(mdf());
  Args = SealAlloc(Args, "@pkdcalc", mdsize, 'b');
  pkd_calc_vf = SealSearch(Args, "@pkdcalc");
  EVP_DigestFinal(ctx, pkd_calc_vf->Value, &mdsize);
  EVP_MD_CTX_free(ctx);

  // The calculated digest is binary. Encode it as base64 to compare with pkd.
  SealBase64Encode(pkd_calc_vf);
  pkdCalc = SealGetText(Args, "@pkdcalc");

  // Compare digests
  if (strcmp(pkd, pkdCalc) != 0) {
    Args = SealSetText(Args, "@error", "Public key digest (pkd) mismatch");
  }

  // Clean up temporary fields
  SealDel(Args, "@pkbin");
  SealDel(Args, "@pkdcalc");

  return Args;
} /*SealInlineVerify*/