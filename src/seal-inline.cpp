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

  /*****
   Nothing to do if:
   - Not inline format
   - pk is already defined via command line parameter
   *****/
  if (!SealSearch(Args,"@inline") || SealGetText(Args,"pk")) { return Args; }

  keypair = SealLoadPrivateKey(Args);
  // TBD: Needs to handle remote signing!
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
 Sets: @inlineauth if matched.
 ********************************************************/
sealfield * SealInlineAuthenticate    (sealfield *Rec, sealfield *Dns)
{
  char *rec_pk, *dns_pkd, *dns_pka;
  const EVP_MD* (*mdf)(void);
  char *pkdCalc;
  sealfield *sf_pbin, *sf_pkbin;
  sealfield *pk_bin_vf, *pkd_calc_vf;

  // Get parameters
  rec_pk = SealGetText(Rec, "pk");
  dns_pkd = SealGetText(Dns, "pkd");
  dns_pka = SealGetText(Dns, "pka");
  Rec = SealDel(Rec, "@inlineauth");

  // If DNS p matches Rec pk, then it's a match
  sf_pbin = SealSearch(Dns, "@p-bin");
  sf_pkbin = SealSearch(Rec, "@pk-bin");
  if (sf_pbin && sf_pkbin)
    {
    if ((sf_pbin->ValueLen == sf_pkbin->ValueLen) &&
	!memcmp(sf_pbin->Value, sf_pkbin->Value, sf_pbin->ValueLen))
	{
	Rec = SealSetText(Rec, "@inlineauth", "true");
	return Rec;
	}
    }

  // If any are missing, we can't verify.
  if (!rec_pk || !dns_pkd || !dns_pka)
    {
    // This is not an error, just means it's not an inline signature
    // or the DNS record is missing pkd/pka.
    //Rec = SealSetText(Rec, "@error", "Public key digest unavailable");
    return Rec;
    }

  // Determine digest algorithm from pka
  mdf = SealGetMdfFromString(dns_pka);
  if (!mdf) {
    //Rec = SealSetText(Rec, "@error", "Unsupported public key digest algorithm (pka)");
    return Rec;
  }

  // The public key 'pk' is base64 encoded. We need its binary form.
  Rec = SealSetText(Rec, "@pkbin", rec_pk);
  pk_bin_vf = SealSearch(Rec, "@pkbin");
  SealBase64Decode(pk_bin_vf);

  if (SealGetSize(Rec, "@pkbin") <= 0) {
    //Rec = SealSetText(Rec, "@error", "Failed to base64 decode public key (pk)");
    Rec = SealDel(Rec, "@pkbin");
    return Rec;
  }

  // Calculate digest of the public key
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  EVP_DigestInit(ctx, mdf());
  EVP_DigestUpdate(ctx, pk_bin_vf->Value, pk_bin_vf->ValueLen);

  unsigned int mdsize = EVP_MD_size(mdf());
  Rec = SealAlloc(Rec, "@pkdcalc", mdsize, 'b');
  pkd_calc_vf = SealSearch(Rec, "@pkdcalc");
  EVP_DigestFinal(ctx, pkd_calc_vf->Value, &mdsize);
  EVP_MD_CTX_free(ctx);

  // The calculated digest is binary. Encode it as base64 to compare with pkd.
  SealBase64Encode(pkd_calc_vf);
  pkdCalc = SealGetText(Rec, "@pkdcalc");

  // Compare digests
  if (!strcmp(dns_pkd, pkdCalc))
    {
    Rec = SealSetText(Rec, "@inlineauth", "true");
    }
  else
    {
    //Rec = SealSetText(Rec, "@error", "Public key digest (pkd) mismatch");
    }

  // Clean up temporary fields
  Rec = SealDel(Rec, "@pkbin");
  Rec = SealDel(Rec, "@pkdcalc");

  return Rec;
} /* SealInlineAuthenticate() */
