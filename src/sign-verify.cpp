/************************************************
 SEAL: Code to verify signatures.
 See LICENSE
 ************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h> // memset

// for DNS
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <ctype.h>

// for OpenSSL v3
#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

// for SEAL
#include "seal.hpp"
#include "seal-dns.hpp"
#include "seal-parse.hpp"
#include "sign.hpp"
#include "files.hpp"

#if defined(__linux__) && !defined(__GLIBC__)
static inline int res_ninit(res_state statp)
{
	int rc = res_init();
	if (statp != &_res) { memcpy(statp, &_res, sizeof(*statp)); }
	return rc;
}

static inline int res_nclose(res_state statp)
{
	if (!statp) { return -1; }
	if (statp != &_res) { memset(statp, 0, sizeof(*statp)); }
	return 0;
}

static inline int res_nquery(res_state statp,
	          const char *dname, int nclass, int type,
	          unsigned char *answer, int anslen)
{
	if (!statp) { return -1; }
	return(res_query(dname, nclass, type, answer, anslen));
}
#endif

#pragma GCC visibility push(hidden)
/********************************************************
 _SealVerifyShow(): Display results
 ErrorMsg is set when the signature is invalid.
 ********************************************************/
void	_SealVerifyShow	(sealfield *Rec, int rc, long signum, const char *Msg)
{
  sealfield *vf;
  char *Txt;
  unsigned int i;

  // Show header
  printf(" SEAL record #%ld is ",signum);
  if (rc & 0x10) { printf("revoked"); }
  else if (rc & 0x01) { printf("invalid"); }
  else if (rc & 0x02) { printf("unsigned"); }
  else if (rc & 0x04) { printf("not validated"); }
  else if (rc & 0x08) { printf("not autenticated"); }
  else { printf("valid"); }
  if (Msg) { printf(": %s\n",Msg); }

  // Show digest (if verbose)
  if (Verbose)
	{
	vf = SealSearch(Rec,"@PublicAlgName");
	if (vf)
	  {
	  printf("  Signature Algorithm: %s, %u bits\n",vf->Value,(unsigned int)SealGetIindex(Rec,"@PublicAlgBits",0));
	  }

	vf = SealSearch(Rec,"da");
	if (vf)
	  {
	  printf("  Digest Algorithm: %s\n",vf->Value);
	  }

	vf = SealSearch(Rec,"@digest1");
	if (vf)
	  {
	  printf("  Digest: ");
	  for(i=0; i < vf->ValueLen; i++) { printf("%02x",vf->Value[i]); }
	  printf("\n");
	  }
	vf = SealSearch(Rec,"@digest2");
	if (vf)
	  {
	  printf("  Double Digest: ");
	  for(i=0; i < vf->ValueLen; i++) { printf("%02x",vf->Value[i]); }
	  printf("\n");
	  }

	vf = SealSearch(Rec,"@digestrange");
	if (vf && (vf->ValueLen > 0)) // better always be defined!
	  {
	  size_t *rangeval, MaxRange;

	  rangeval = (size_t*)(vf->Value);
	  MaxRange = vf->ValueLen / sizeof(size_t);
	  printf("  Signed Bytes: ");
	  for(i=0; i < MaxRange; i++)
	    {
	    if (i%2) { printf("-%lu",(unsigned long)(rangeval[i])-1); } // end
	    else // start
	      {
	      if (i > 0) { printf(", "); }
	      printf("%lu",(unsigned long)(rangeval[i]));
	      }
	    }
	  printf("\n");
	  }
	}

  // Show range
  Txt = SealGetText(Rec,"@sflags0");
  if (Txt)
	{
	printf("  Signature Spans: ");
	if (strchr(Txt,'F')) { printf("Start of file"); }
	else if (strchr(Txt,'P')) { printf("Start of previous signature"); }
	else if (strchr(Txt,'p')) { printf("End of previous signature"); }
	else if (strchr(Txt,'S')) { printf("Start of signature"); }
	else if (strchr(Txt,'s')) { printf("End of signature"); }
	else if (strchr(Txt,'f')) { printf("End of file"); }
	else { printf("Absolute offset"); }
	printf(" to ");
	Txt = SealGetText(Rec,"@sflags1");
	if (strchr(Txt,'f')) { printf("end of file"); }
	else if (strchr(Txt,'s')) { printf("end of signature"); }
	else if (strchr(Txt,'S')) { printf("start of signature"); }
	else if (strchr(Txt,'p')) { printf("end of previous signature"); }
	else if (strchr(Txt,'P')) { printf("start of previous signature"); }
	else if (strchr(Txt,'F')) { printf("start of file"); }
	else { printf("absolute offset"); }
	printf("\n");
	}

  // If show details
	{
	Txt = SealGetText(Rec,"@sigdate");
	if (Txt && Txt[0])
	  {
	  if (rc & 0x07) { printf("  Unverified Signed"); }
	  else { printf("  Signed"); }
	  printf(" on %.4s-%.2s-%.2s",Txt,Txt+4,Txt+6);
	  printf(" at %.2s:%.2s:%.2s",Txt+8,Txt+10,Txt+12);
	  if (Txt[14]=='.') { printf("%s",Txt+14); }
	  printf(" GMT\n");
	  }

	Txt = SealGetText(Rec,"d");
	if (rc & 0x07) { printf("  Unverified Signed By:"); }
	else { printf("  Signed By:"); }
	printf(" %s",Txt);

	Txt = SealGetText(Rec,"id");
	if (Txt && Txt[0])
	  {
	  printf(" for user %s",Txt);
	  }
	printf("\n");

	Txt = SealGetText(Rec,"copyright");
	if (Txt && Txt[0])
	  {
	  if (rc & 0x07) { printf("  Unverified Copyright:"); }
	  else { printf("  Copyright:"); }
	  printf(" %s\n",Txt);
	  }

	Txt = SealGetText(Rec,"info");
	if (Txt && Txt[0])
	  {
	  if (rc & 0x07) { printf("  Unverified Comment:"); }
	  else { printf("  Comment:"); }
	  printf(" %s\n",Txt);
	  }
	}
} /* _SealVerifyShow() */

/********************************************************
 _SealValidateRevoke(): Given seal record with DNS results,
 see if it is revoked.
 This is called AFTER checking the signatures.
 Returns:
   Specific revokes are flagged by '@revoke'
   Errors are detailed in '@error'
 On success, decoded signature is in '@sigbin' (and no '@error').
 ********************************************************/
sealfield *	_SealValidateRevoke	(sealfield *Rec, sealfield *dnstxt)
{
  bool IsRevoke=false;
  char *SigDate;
  char *Revoke;

  if (!Rec || !dnstxt) // should never happen
    {
    Rec = SealSetText(Rec,"@error","no record to check");
    return(Rec);
    }

  Revoke = SealGetText(dnstxt,"r");
  SigDate = SealGetText(Rec,"@sigdate"); // may not exist

  if (!Revoke) { ; } // no revoke? Done!
  else if (!Revoke[0] || !strcmp(Revoke,"revoke")) { IsRevoke=true; } // no date? Revoke!
  else if (!SigDate) { IsRevoke=true; } // No date? Revoke!
  else // See if sigdate predates revocation
    {
    int minlen,minlen1,minlen2;
    minlen1 = strlen(SigDate);
    minlen2 = strlen(Revoke);
    minlen = (minlen1 < minlen2) ? minlen1 : minlen2;
    if (strncmp(SigDate,Revoke,minlen) >= 0) { IsRevoke=true; } // if it's revoked
    // else: Not revoked!
    }

  if (IsRevoke) // if it's revoked, tag it
    {
    Rec = SealSetText(Rec,"@revoke","public key revoked");
    }

  return(Rec);
} /* _SealValidateRevoke() */

/********************************************************
 _SealValidateSig(): Given seal record with DNS results,
 and decoded binary signature, see if it validates!!!
 Called by SealValidate().
 This is only called if SealValidateDecodeParts() worked.
 Returns: Errors are detailed in '@error', revoke is set in '@revoke'.
 ********************************************************/
sealfield *	_SealValidateSig	(sealfield *Rec, sealfield *dnstxt)
{
  const EVP_MD* (*mdf)(void);
  EVP_PKEY *PubKey=NULL;
  EVP_PKEY_CTX *PubKeyCtx=NULL;
  char *keyalg, *digestalg;
  sealfield *sigbin, *digestbin, *pubkey;
  unsigned long e;

  /*****
   If you're calling this function, then we have:
   Correct dnstxt record
   '@sigbin' = binary signature
   '@digest1' = binary digest
   '@digest2' = (optional) binary digest
   'ka' = key algorthtm
   And we know the record is not revoked.

   Use the public key with the key algorith to decode the signature.
   It should match the digest.
     decode_ka(publicbin,sigbin) == digest
   *****/

  digestalg = SealGetText(Rec,"da"); // SEAL's 'da' parameter
  mdf = SealGetMdfFromString(digestalg);
  if (!mdf)
	{
	fprintf(stderr," ERROR: Unsupported digest algorithm (da=%s).\n",digestalg);
	exit(0x80);
	}

  // Prepare the public key
  pubkey = SealSearch(dnstxt,"@p-bin");
  if (!pubkey) // should never happen
    {
    Rec = SealSetText(Rec,"@error","no public key found");
    goto Done;
    }

  // Check if ka matches DNS
  keyalg = SealGetText(Rec,"ka"); // get seal record's ka; better exist!
  if (!keyalg) // should never happen
    {
    Rec = SealSetText(Rec,"@error","no public key algorithm defined");
    goto Done;
    }

  sigbin = SealSearch(Rec,"@sigbin");
  if (!sigbin) // should never happen
    {
    Rec = SealSetText(Rec,"@error","no signature found");
    goto Done;
    }

  digestbin = SealSearch(Rec,"@digest2");
  if (!digestbin) { digestbin = SealSearch(Rec,"@digest1"); }
  if (!digestbin) // should never happen
    {
    Rec = SealSetText(Rec,"@error","no digest found");
    goto Done;
    }

  // Load public key into EVP_PKEY structure
  {
  /* Use BIO (binary I/O handler) to import the data */
  BIO *bio;
  bio = BIO_new_mem_buf(pubkey->Value, pubkey->ValueLen);
  if (!bio)
	{
	Rec = SealSetText(Rec,"@error","failed to load public key into memory");
	goto Done;
	}
  /* Convert BIO to public key */
  PubKey = d2i_PUBKEY_bio(bio, NULL);
  BIO_free(bio); // done with BIO
  }

  if (!PubKey)
	{
	Rec = SealSetText(Rec,"@error","failed to import public key");
	goto Done;
	}

  // Prepare public key for verifying
  PubKeyCtx = EVP_PKEY_CTX_new(PubKey,NULL);
  if (!PubKeyCtx) // could happen if key is corrupt
	{
	fprintf(stderr," ERROR: Unable to create validation context.\n");
	e = ERR_get_error();
	Rec = SealAddText(Rec,"@error"," (");
	Rec = SealAddText(Rec,"@error",ERR_lib_error_string(e));
	Rec = SealAddText(Rec,"@error",": ");
	Rec = SealAddText(Rec,"@error",ERR_reason_error_string(e));
	Rec = SealAddText(Rec,"@error",")");
	exit(0x80);
	}
  if (EVP_PKEY_verify_init(PubKeyCtx) != 1)
	{
	fprintf(stderr," ERROR: Unable to initialize validation context.\n");
	e = ERR_get_error();
	Rec = SealAddText(Rec,"@error"," (");
	Rec = SealAddText(Rec,"@error",ERR_lib_error_string(e));
	Rec = SealAddText(Rec,"@error",": ");
	Rec = SealAddText(Rec,"@error",ERR_reason_error_string(e));
	Rec = SealAddText(Rec,"@error",")");
	exit(0x80);
	}

  // Record info about the crypto
  Rec = SealSetText(Rec,"@PublicAlgName",EVP_PKEY_get0_type_name(PubKey));
  Rec = SealSetIindex(Rec,"@PublicAlgBits",0,(size_t)EVP_PKEY_get_bits(PubKey));

  // RSA needs padding
  if (!strcmp(keyalg,"rsa"))
    {
    if (EVP_PKEY_CTX_set_rsa_padding(PubKeyCtx, RSA_PKCS1_PADDING) != 1)
	{
	fprintf(stderr," ERROR: Unable to initialize RSA validation.\n");
	e = ERR_get_error();
	Rec = SealAddText(Rec,"@error"," (");
	Rec = SealAddText(Rec,"@error",ERR_lib_error_string(e));
	Rec = SealAddText(Rec,"@error",": ");
	Rec = SealAddText(Rec,"@error",ERR_reason_error_string(e));
	Rec = SealAddText(Rec,"@error",")");
	exit(0x80);
	}
    } // setup rsa padding

  if (EVP_PKEY_CTX_set_signature_md(PubKeyCtx, mdf()) != 1)
	{
	fprintf(stderr," ERROR: Unable to set digest for validation.\n");
	e = ERR_get_error();
	Rec = SealAddText(Rec,"@error"," (");
	Rec = SealAddText(Rec,"@error",ERR_lib_error_string(e));
	Rec = SealAddText(Rec,"@error",": ");
	Rec = SealAddText(Rec,"@error",ERR_reason_error_string(e));
	Rec = SealAddText(Rec,"@error",")");
	exit(0x80);
	}

  // Check the signature!
  sigbin = SealSearch(Rec,"@sigbin");
  digestbin = SealSearch(Rec,"@digest2");
  if (!digestbin) { digestbin = SealSearch(Rec,"@digest1"); }
  if (EVP_PKEY_verify(PubKeyCtx, sigbin->Value, sigbin->ValueLen, digestbin->Value, digestbin->ValueLen) != 1)
	{
	Rec = SealSetText(Rec,"@error","signature mismatch");
	}

  // Made it here? It validatd!
  // Check if it is revoked.
  Rec = _SealValidateRevoke(Rec,dnstxt);

Done:
  // Free structures when done.
  if (PubKeyCtx) { EVP_PKEY_CTX_free(PubKeyCtx); }
  if (PubKey) { EVP_PKEY_free(PubKey); }
  return(Rec);
} /* _SealValidateSig() */

#pragma GCC visibility pop

/********************************************************
 SealValidateDecodeParts(): Given seal record with signature, decode the signature.
 NOTE: This does NOT check the crypto!
 Returns: Errors are detailed in '@error'
 On success:
   Decoded signature is in '@sigbin'
   Any timestamp is in '@sigdate'
   and no '@error'
 ********************************************************/
sealfield *	SealValidateDecodeParts	(sealfield *Rec)
{
  char *SigFormat;
  char *Sig;
  size_t siglen,datelen=0;
  SealSignatureFormat sigFormat;

  if (!Rec) // should never happen
    {
    Rec = SealSetText(Rec,"@error","no record to check");
    return(Rec);
    }

  SigFormat = SealGetText(Rec,"sf"); // always defined

  Sig = SealGetText(Rec,"s");
  if (!Sig)
    {
    Rec = SealSetText(Rec,"@error","signature not found");
    return(Rec);
    }
  siglen = strlen(Sig);

  // Verify the format
  datelen=0; // if it's > 0, then there's a date string
  Rec = SealDel(Rec,"@sigdate");
  if (SigFormat && !strncmp(SigFormat,"date",4))
    {
    // Make sure the date is correct
    datelen = 14; // YYYYMMDDhhmmss
    if (isdigit(SigFormat[4]))
      {
      datelen += 1 + SigFormat[4]-'0';
      }

    // date + ":" + sig; the sig better be at least 1 character
    if ((siglen <= datelen+2) || (Sig[datelen]!=':') ||
	((datelen > 14) && (Sig[14]!='.')) )
      {
      Rec = SealSetText(Rec,"@error","signature date does not match the specified format");
      return(Rec);
      }
    Rec = SealSetTextLen(Rec,"@sigdate",datelen,Sig);
    datelen++; // skip the ':'
    }

  // Decode to binary
  if (Sig)
    {
    /*****
     Decode the signature into binary
     I should be doing this in _SealValidateSig(), but I've
     already loaded the signature and datelen here.
     (No need to repeat this process.)
     *****/
    Rec = SealDel(Rec,"@sigbin");
    Rec = SealSetBin(Rec,"@sigbin",siglen-datelen,(byte*)Sig+datelen);

    // Remove any padding
    sealfield *s;
    s = SealSearch(Rec,"@sigbin");
    while((s->ValueLen > 1) && isspace(s->Value[s->ValueLen-1])) { s->ValueLen--; }

    // Decode the signature
    sigFormat = SealGetSF(SigFormat);
    if (sigFormat == INVALID) 
      {
      Rec = SealSetText(Rec, "@error", "unsupported signature encoding");
      }
    SealDecode(SealSearch(Rec, "@sigbin"), sigFormat);

    if (SealSearch(Rec, "@sigbin")->ValueLen < 1) 
      {
      if (sigFormat == BASE64) 
        {
        Rec = SealSetText(Rec, "@error", "base64 signature failed to decode");
        } 
      else if (sigFormat == HEX_LOWER || sigFormat == HEX_UPPER) 
        {
        Rec = SealSetText(Rec, "@error", "hex signature failed to decode");
        }
    }

    // To help with debugging
    sealfield *sf;
    sf = SealSearch(Rec,"@sigbin");
    if (sf) { sf->Type = 'x'; }
    } // decode to binary

  return(Rec);
} /* SealValidateDecodeParts() */

/********************************************************
 SealVerify(): Given seal record, see if it validates.
 NOTE: Permits a preface file (MmapPre) for sidecar support.
 Generates output text!
 ********************************************************/
sealfield *	SealVerify	(sealfield *Rec, mmapfile *Mmap, mmapfile *MmapPre)
{
  char *ErrorMsg=NULL;
  char *RevokeMsg=NULL;
  sealfield *dnstxt=NULL;
  int dnsnum; // which dns record number?
  long signum; // signature number
  char *rec_sv,*dns_sv; // for matching seal version strings
  char *rec_id,*dns_id; // for matching uid strings
  char *rec_ka,*dns_ka; // for matching ka strings
  char *rec_kv,*dns_kv; // for matching kv strings
  char *dns_str;
  bool IsValid=true; // assume it is valid

  if (!Rec) { return(Rec); }

  /*****
   Signature numbering begins a "1".
   If it's less than 1, then no signature was found.
   If it's 1, then check if it covers the start of the file.
   *****/
  signum = SealGetIindex(Rec,"@s",2);
  if (signum < 1) // happens if the seal record is corrupted
    {
    printf(" WARNING: Invalid SEAL record count (%ld).\n",signum);
    return(Rec);
    }

  /* Compute current digest */
  ErrorMsg = SealGetText(Rec,"@error");

  // Check for prepending: signatures should cover start of file
  if (signum == 1)
    {
    if (!strchr(SealGetText(Rec,"b"),'F'))
	{
	printf("  WARNING: SEAL record #%ld does not cover the start of file. Vulnerable to prepending attacks.\n",signum);
	}
    }
  else // if (signum > 1)
    {
    if (!strchr(SealGetText(Rec,"b"),'F') && !strchr(SealGetText(Rec,"b"),'P'))
	{
	printf("  WARNING: SEAL record #%ld does not cover the previous signature. Vulnerable to insertion attacks.\n",signum);
	}
    }

  /* Decode the encoded components */
  if (!ErrorMsg)
	{
	// Decode parts, including identifying any "@sigdate"
	// Also ensures that a signature "s" exists.
	Rec = SealValidateDecodeParts(Rec);
	ErrorMsg = SealGetText(Rec,"@error");
	}

  /* Compute digests */
  if (!ErrorMsg)
	{
	// @sigdate set by SealValidateDecodeParts
	Rec = SealDigest(Rec,Mmap,MmapPre);

	// Retain flags
	Rec = SealSetText(Rec,"@sflags",SealGetText(Rec,"@sflags0"));
	Rec = SealAddC(Rec,"@sflags",'~');
	Rec = SealAddText(Rec,"@sflags",SealGetText(Rec,"@sflags1"));
	Rec = SealAddC(Rec,"@sflags",'|');

	// apply sigdate:userid: as needed
	Rec = SealDoubleDigest(Rec);
	ErrorMsg = SealGetText(Rec,"@error");
	}

  /*****
   DNS...
   There may be multiple DNS records.
   Find the first one that verifies.
   If ANY have a global revoke, track it, but still check if any verify.
   Only keep the error if NONE of them verify.

   This sets multiple output flags:
     @revoke-global: If set, then any non-verified signature is a revoke
     @revoke: If set, then the signature is revoked.
     @error: If set and no dnstxt, then this denotes the error.
     dnstxt: If set, then the signature validated. (May still have @revoke or @error.)
   *****/
  if (!ErrorMsg) // only loop if there's no error (yet)
    {
    // foreach DNS record, load dns txt record. Stop when there are no more records.
    rec_sv = SealGetText(Rec,"seal");
    rec_id = SealGetText(Rec,"uid");
    rec_ka = SealGetText(Rec,"ka");
    rec_kv = SealGetText(Rec,"kv");
    for(dnsnum=0; (dnstxt=SealDNSGet(Rec,dnsnum)) != NULL; dnsnum++) // foreach dns record...
      {
      /* Copy DNS components to the record for verifying */
      Rec = SealDel(Rec,"@error"); // assume no error so far

      /******************************************************
       Check if the DNS record applies to this SEAL record.
       ******************************************************/
      // Must be same seal version
      // seal version must match (default to "1")
      dns_sv = SealGetText(dnstxt,"seal");
      if (!rec_sv || !dns_sv) { continue; } // both must be defined
      else if (!strcmp(dns_sv,rec_sv)) { ; } // explicit match
      else { continue; } // missed

      // If DNS has ka, then seal record must match
      dns_ka = SealGetText(dnstxt,"ka");
      if (dns_ka && (!rec_ka || strcmp(dns_ka,rec_ka))) { continue; }

      // If DNS has a uid, then seal record must match
      dns_id = SealGetText(dnstxt,"uid");
      if (dns_id && (!rec_id || strcmp(dns_id,rec_id))) { continue; }

      // kv must match (default to "1")
      dns_kv = SealGetText(dnstxt,"kv");
      if (rec_kv && dns_kv && !strcmp(dns_kv,rec_kv)) { ; } // explicit match
      else if (!rec_kv && !dns_kv) { ; } // dual implicit match
      else if (rec_kv && !dns_kv && !strcmp(rec_kv,"1")) { ; } // implicit match
      else if (!rec_kv && dns_kv && !strcmp(dns_kv,"1")) { ; } // implicit match
      else { continue; } // missed

      /*****
       TBD: If Rec contains inline-pubkey, then either:
       (A) match full p=, or
       (B) match digest using pka= and pkd=
       If neither matches, then it doesn't apply (continue).
       *****/

      /*********************************
       All mandatory fields matches!
       *********************************/
      // Check for global revoked when no pubkey defined
      dns_str = SealGetText(dnstxt,"p");
      if (!dns_str) { dns_str = SealGetText(dnstxt,"pkd"); }
      if (!dns_str || !dns_str[0] || !strcmp(dns_str,"revoke"))
        {
	Rec = SealSetText(Rec,"@revoke-global","domain default revoke");
	continue;
	}

      // There's a public key! See if it matched
      /* Check if the decoded digest matches the known digest. */
      Rec = _SealValidateSig(Rec,dnstxt);
      if (SealGetText(Rec,"@revoke")) { break; } // It is revoked!
      if (!SealGetText(Rec,"@error")) { break; } // It worked!
      } // foreach DNS record
    } // if checking DNS

  // Report any errors or findings
  RevokeMsg = SealGetText(Rec,"@revoke");
  ErrorMsg = SealGetText(Rec,"@error");
  if (RevokeMsg) // If no valid DNS and there's a revoke, then report it!
	{
	IsValid = false;
	ReturnCode |= 0x10; // at least one file is invalid (validated, but revoked)
	_SealVerifyShow(Rec,0x10,signum,RevokeMsg);
	}
  else if (ErrorMsg) // Else: If there is any error, then report it!
	{
	IsValid = false;
	ReturnCode |= 0x01; // at least one file is invalid
	_SealVerifyShow(Rec,0x01,signum,ErrorMsg);
	}
  else if (dnstxt) // No error and no revoke! There's a match!
	{
	_SealVerifyShow(Rec,0,signum,NULL);
	}
  else // Failed to verify against dns
	{
	RevokeMsg = SealGetText(Rec,"@revoke-global");
	if (RevokeMsg)
	  {
	  IsValid = false;
	  ReturnCode |= 0x11; // at least one file is invalid
	  _SealVerifyShow(Rec,0x11,signum,RevokeMsg);
	  }
	else if (SealSearch(Rec,"pk")) // was this a public key authentication?
	  {
	  ReturnCode |= 0x08; // at least one file could not be attributed
	  _SealVerifyShow(Rec,0x08,signum,"could not validate");
	  }
	else
	  {
	  ReturnCode |= 0x04; // at least one file could not be validated
	  _SealVerifyShow(Rec,0x04,signum,"could not validate");
	  }
	}

  /* Verify the src details, if present.
     Failure to verify warns, does not error */
  if (IsValid)
    {
    SealSrcVerify(Rec);
    }

  return(Rec);
} /* SealVerify() */

/********************************************************
 SealVerifyFinal(): Given seal record, see if it covers entire file.
 Returns: true if valid.
 Generates output text!
 ********************************************************/
bool	SealVerifyFinal	(sealfield *Rec)
{
  if (!Rec) { return(false); }
  if (!strchr(SealGetText(Rec,"@sflags"),'f')) // signatures should cover end of file
	{
	printf(" WARNING: SEAL records do not finalize the file. Data may be appended.\n");
	return(false);
	}
  return(true);
} /* SealVerifyFinal() */

/********************************************************
 SealVerifyBlock(): Given block of data, scan it for every
 possible SEAL record. (There could be more than one.)
 BlockStart and BlockEnd are relative to Mmap.
 Returns: updated sealfield.
 Generates output text!
 ********************************************************/
sealfield *	SealVerifyBlock	(sealfield *Args,
				 size_t BlockStart, size_t BlockEnd,
				 mmapfile *Mmap, mmapfile *MmapPre)
{
  size_t RecEnd;
  sealfield *Rec=NULL;

  while(BlockStart < BlockEnd) 
    {
    Rec = SealParse(BlockEnd-BlockStart, Mmap->mem+BlockStart, BlockStart, Args);
    if (!Rec) { goto Abort; } // Nothing found

    // Keep srcf if it came from Args
    Rec = SealCopy2(Rec,"srcf",Args,"srcf");

    // Found a signature!  Verify the data!
    Rec = SealVerify(Rec,Mmap,MmapPre);

    // Iterate on remainder
    RecEnd = SealGetIindex(Rec,"@RecEnd",0);
    if (RecEnd <= 0) { RecEnd=1; } // should never happen, but if it does, stop infinite loops
    BlockStart += RecEnd;
    Rec = SealDel(Rec,"@RecEnd");
 
    // Retain state
    Args = SealCopy2(Args,"@s",Rec,"@s");
    Args = SealCopy2(Args,"@p",Rec,"@s");
    Args = SealAddText(Args,"@sflags",SealGetText(Rec,"@sflags"));
    Args = SealDel(Args,"@RecEnd");

    // Clean up
    SealFree(Rec); Rec=NULL;
    }

Abort:
  return(Args);
} /* SealVerifyBlock() */
