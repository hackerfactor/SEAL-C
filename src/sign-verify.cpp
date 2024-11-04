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

// for SEAL
#include "seal.hpp"
#include "seal-parse.hpp"
#include "sign.hpp"
#include "files.hpp"

/********************************************************
 SealGetDNSfile(): Given a file that goes to DNS, use it.
 ********************************************************/
sealfield *	SealGetDNSfile	(sealfield *Rec)
{
  sealfield *R, *Reply;
  mmapfile *Mmap;
  const char *fname;

  fname = SealGetText(Rec,"@pubkeyfile");
  if (!fname) { return(NULL); }

  Mmap = MmapFile(fname,PROT_READ);
  if (!Mmap) { return(NULL); }

  size_t len;
  for(len=Mmap->memsize; len > 0; len--)
    {
    if (!isspace(Mmap->mem[len-1])) { break; }
    }

  R = NULL;
  R = SealSetText(R,"@dns","<seal ");
  R = SealAddBin(R,"@dns",len,Mmap->mem);
  R = SealAddText(R,"@dns"," />");
  Reply = SealParse(R->ValueLen,R->Value,0,NULL);
  SealFree(R);
  MmapFree(Mmap);

  Reply = SealMove(Reply,"@public","p");
  for(R=Reply; R; R=R->Next)
    {
    Rec = SealCopy2(Rec,R->Field,R,R->Field);
    }
  SealFree(Reply);

  return(Rec);
} /* SealGetDNSfile() */

/********************************************************
 SealGetDNS(): Given a hostname, get the first matching key from DNS.
 Returns: Public key in '@public', revoke in '@revoke'.
 Errors are detailed in '@error'
 ********************************************************/
sealfield *	SealGetDNS	(sealfield *Rec)
{
  char *Domain;
  if (!Rec) { return(Rec); } // must be defined
  if (!SealSearch(Rec,"uid")) { Rec=SealSetText(Rec,"uid",""); } // default uid
  if (!SealSearch(Rec,"kv")) { Rec=SealSetText(Rec,"kv","1"); } // default key version

  // For speed: Check if the same DNS key exists
  Rec = SealCopy(Rec,"@dnscache","seal");
  Rec = SealAddText(Rec,"@dnscache",":");
  Rec = SealAddText(Rec,"@dnscache",SealGetText(Rec,"d"));
  Rec = SealAddText(Rec,"@dnscache",":");
  Rec = SealAddText(Rec,"@dnscache",SealGetText(Rec,"kv"));
  Rec = SealAddText(Rec,"@dnscache",":");
  Rec = SealAddText(Rec,"@dnscache",SealGetText(Rec,"ka"));
  Rec = SealAddText(Rec,"@dnscache",":");
  Rec = SealAddText(Rec,"@dnscache",SealGetText(Rec,"uid"));
  if (!SealCmp(Rec,"@dnscache","@dnscachelast"))
	{
	return(Rec);
	}

  // Prepare for new DNS lookup
  Rec = SealMove(Rec,"@dnscachelast","@dnscache");
  Rec = SealDel(Rec,"@public");
  Rec = SealDel(Rec,"@publicbin");
  Rec = SealDel(Rec,"@revoke");
  Domain = SealGetText(Rec,"d"); // must be defined
  if (!Domain || !Domain[0])
    {
    Rec = SealSetText(Rec,"@error","no domain specified");
    return(Rec);
    }

  // Do the DNS query!
  sealfield *vf, *Reply=NULL;
  sealfield *vBuf=NULL;
  unsigned char Buffer[16384]; // permit 16K buffer for DNS reply (should be overkill)
  const char *s;
  int Txti; // DNS unparsed (input) TXT as offset into Buffer
  int size;
  ns_msg nsMsg;
  ns_rr rr; // dns response record
  struct __res_state dnsstate;
  int MsgMax, count, c;

  // Check for static file
  Reply = SealGetDNSfile(Rec);
  if (Reply) { return(Reply); }

  // Do DNS
  memset(&dnsstate, 0, sizeof(dnsstate));
  if (res_ninit(&dnsstate) < 0)
    {
    // Should never happen
    fprintf(stderr,"ERROR: Unable to initialize DNS lookup. Aborting.\n");
    exit(1);
    }

  memset(&Buffer, 0, 16384);
  MsgMax = res_nquery(&dnsstate, Domain, C_IN, T_TXT, Buffer, 16384-1);
  if (MsgMax > 0) // found something!
    {
    /*****
     Parse the record
     DNS uses pascal strings: 1 byte length + data

     Okay, so I asked for TXT records (res_nquery T_TXT).
     But the DNS server can return ANYTHING.

     There are four sections in the reply message:
       QUERY, ANSWER, AUTHORITY, and ADDITIONAL.
     Each says how many records they can return.
     I only care about the ANSWER section (ns_s_an).
     1. Find out how many answers (ns_msg_count with ns_s_an).
     2. For each answer, make sure the format is valid and it's a TXT.
	Skip anything else.
     3. DNS replies use a simple "reuse" approach to reduce the reply size.
	(They call it "compressed" but it's not compressed in the traditional sense.)
	The values are stored in a pascal string:
	  1 byte length + data
	A long value may be: 1 data 1 data 1 data 0
	But let's say that two records return similar strings, like
	"host1.hackerfactor.com" and "host2.hackerfactor.com".
	Then it can store a pointer to previous content.
	E.g.:
	  5 "host1" 17 ".hackerfactor.com" 0
	  5 "host2" 0xc0 jump to previous 17 ".hackerfactor.com" 0

     You can either try parsing this manually, or use the undocumented
     ns_name_uncompress() function. (undocumented because there's no
     man-page for it; never has been since the internet was a baby, and
     it may not exist on every platform).

     I use a sealfield and just append text to it.
     To stop infinite loops, I stop at 4K (+/- 256).
     *****/
    if (ns_initparse(Buffer, MsgMax, &nsMsg)) { goto Done; } // failed?
    // How many ANSWER replies?
    count = ns_msg_count(nsMsg, ns_s_an);
    for(c=0; c < count; c++)
      {
      if (ns_parserr(&nsMsg,ns_s_an,c,&rr)) { continue; } // if failed to parse
      if (ns_rr_type(rr) != ns_t_txt) { continue; } // must be TXT

      if (Reply) { SealFree(Reply); Reply=NULL; }
      if (vBuf) { SealFree(vBuf); vBuf=NULL; }

      // ns_rr_rdata returns length + string
      // Find text position as offset into Buffer
      s = (const char *)ns_rr_rdata(rr);
      if (!s) { continue; } // bad data

      vBuf = SealSetText(vBuf,"r","<seal ");
      Txti = (unsigned char*)s - Buffer; // s is located somewhere in Buffer; Txti is the offset
      while((Txti < MsgMax) && (SealGetSize(vBuf,"r") < 4096))
	{
	size = Buffer[Txti]; Txti++;
	if (size <= 0) { break; } // no more data
	else if ((size & 0xf0) == 0xc0) // it's a jump!
	  {
	  if (Txti+1 >= MsgMax) { break; } // overflow
	  Txti = ((size & 0x3f) << 8) | Buffer[Txti]; // find the offset
	  continue;
	  }
	else if (Txti+size > MsgMax) { break; } // read overflow
	vBuf = SealAddTextLen(vBuf,"r",size,(const char*)Buffer+Txti);
	Txti += size;
	if (size < 0xff) { break; }
	}
      vBuf = SealAddText(vBuf,"r"," />");

      // Now I have something in vBuf['r']that looks like "<seal DNS />"
      // Check for SEAL record: must begin with "seal="
      s = SealGetText(vBuf,"r");
      if (strncmp(s+6,"seal=",5)) { SealFree(vBuf); vBuf=NULL; continue; }

      // Parse the DNS record!
      Reply = SealParse(SealGetSize(vBuf,"r"),(byte*)s,0,NULL);
      SealFree(vBuf); vBuf=NULL;
      if (!Reply) { SealFree(Reply); Reply=NULL; continue; } // failed to parse

      // Set defaults
      if (!SealSearch(Reply,"p")) { SealFree(Reply); Reply=NULL; continue; } // no public key!
      while(SealGetSize(Reply,"p")%4) { Reply=SealAddC(Reply,"p",'='); } // base64 padding
      if (!SealSearch(Reply,"kv")) { Reply=SealSetText(Reply,"kv","1"); }
      if (!SealSearch(Reply,"uid")) { Reply=SealSetText(Reply,"uid",""); }

      // Does it match the type of key I want?
      if (SealCmp2(Rec,"seal",Reply,"seal") ||
	  SealCmp2(Rec,"kv",Reply,"kv") ||
	  SealCmp2(Rec,"ka",Reply,"ka") ||
	  SealCmp2(Rec,"uid",Reply,"uid"))
	  { SealFree(Reply); Reply=NULL; continue; } // not a match!

      /*****
       The signature may include a date, such as 202409051239.
       Revocation may include a date in ISO 8601.
       E.g., 2024-04-09T05:12:39
       Reduce any revocation to numeric-only.
       *****/

      // Set any default revokes
      vf = SealSearch(Reply,"p");
      // If public key doesn't exist or is empty or is 'revoke'
      if (!vf || !vf->ValueLen || !strcmp((char*)vf->Value,"revoke"))
	 {
	 // No public key for validation any pre-revocation.
	 // Thus, it is always revoked.
	 Reply = SealSetText(Reply,"r","0"); // always revoked
	 }
      else
	{
	Rec = SealSetText(Rec,"@public",(char*)vf->Value);
	}

      vf = SealSearch(Reply,"r");
      if (vf)
	{
	size_t a,b;
	for(a=b=0; a < vf->ValueLen; a++)
	  {
	  if (!isdigit(vf->Value[a])) { continue; }
	  if (a==b) { continue; }
	  vf->Value[b]=vf->Value[a];
	  b++;
	  }
	if (b < vf->ValueLen)
	  {
	  memset(vf->Value+b,0,vf->ValueLen - b);
	  vf->ValueLen = b;
	  }
	Rec = SealSetText(Rec,"@revoke",(char*)vf->Value);
	}
      goto Done; // Found a result!
      } // foreach dns record
    } // if dns reply

Done:
  res_nclose(&dnsstate);
  if (Reply) { SealFree(Reply); }
  return(Rec);
} /* SealGetDNS() */

/********************************************************
 SealRotateRecords(): Before processing each record, rotate
 the previous '@s' to '@p'.
 ********************************************************/
sealfield *	SealRotateRecords	(sealfield *Rec)
{
  size_t *I;
  Rec = SealCopy(Rec,"@p","@s");
  I = SealGetIarray(Rec,"@s");
  I[0] = I[1] = 0;
  I[2]++;
  return(Rec);
} /* SealRotateRecords() */

/********************************************************
 SealValidateDecodeParts(): Given seal record with signature,
 decode the signature and finalize the digest.
 Returns: Errors are detailed in '@error'
 On success:
   Decoded signature is in '@sigbin'
   Any timestamp is in '@sigdate'
   Decoded digest is in '@digestbin'
   Decoded public key is in '@publicbin'
   and no '@error'
 ********************************************************/
sealfield *	SealValidateDecodeParts	(sealfield *Rec)
{
  char *SigFormat;
  char *Sig;
  size_t siglen,datelen=0;

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
     I should be doing this in SealValidateSig(), but I've
     already loaded the signature and datelen here.
     (No need to repeat this process.)
     *****/
    Rec = SealDel(Rec,"@sigbin");
    Rec = SealSetBin(Rec,"@sigbin",siglen-datelen,(byte*)Sig+datelen);
    if (strstr(SigFormat,"HEX") || strstr(SigFormat,"hex"))
      {
      SealHexDecode(SealSearch(Rec,"@sigbin"));
      if (SealGetSize(Rec,"@sigbin") < 1)
	{
	Rec = SealSetText(Rec,"@error","hex signature failed to decode");
	}
      }
    else if (strstr(SigFormat,"base64"))
      {
      SealBase64Decode(SealSearch(Rec,"@sigbin"));
      if (SealGetSize(Rec,"@sigbin") < 1)
	{
	Rec = SealSetText(Rec,"@error","base64 signature failed to decode");
	}
      }
    else if (strstr(SigFormat,"bin")) { ; } // already handled
    else
      {
      Rec = SealSetText(Rec,"@error","unsupported signature encoding");
      }

    // To help with debugging
    sealfield *sf;
    sf = SealSearch(Rec,"@sigbin");
    if (sf) { sf->Type = 'x'; }
    } // decode to binary

  /*****
   Decode the public key to binary
   *****/
  if (SealSearch(Rec,"@public"))
    {
    Rec = SealCopy(Rec,"@publicbin","@public");
    SealBase64Decode(SealSearch(Rec,"@publicbin"));
    if (SealGetSize(Rec,"@publicbin") <= 0)
	{
	Rec = SealSetText(Rec,"@error","signature failed to base64 decode");
	}
    }

  return(Rec);
} /* SealValidateDecodeParts() */

/********************************************************
 SealValidateRevoke(): Given seal record with DNS results,
 see if it is revoked.
 Returns: Errors are detailed in '@error'
 On success, decoded signature is in '@sigbin' (and not '@error').
 ********************************************************/
sealfield *	SealValidateRevoke	(sealfield *Rec)
{
  bool IsInvalid=false;
  char *SigDate;
  char *Sig;
  char *Revoke;
  char *Public;

  if (!Rec) // should never happen
    {
    Rec = SealSetText(Rec,"@error","no record to check");
    return(Rec);
    }

  Revoke = SealGetText(Rec,"r");
  SigDate = SealGetText(Rec,"@sigdate"); // may not exist
  Sig = SealGetText(Rec,"s");
  Public = SealGetText(Rec,"@public");

  // Verify that components exist
  if (!Sig || !Sig[0])
    {
    Rec = SealSetText(Rec,"@error","no signature found");
    return(Rec);
    }

  /*****
   Multiple conditions and revoke methods.
   1. If there's an "r=", then it's probably revoked.
      Check the date.
      - If there is no date in the sig, then it's revoked.
      - If there is a date and it's newer than r=, then it's revoked.
      - If there is a date and the sig is older, then it's valid.
   2. No r=?  If there is no DNS entry, then it cannot ve validated.
      This isn't revoked; this is unknown.
   3. No r= and public key is not defined
      This isn't revoked; this is unknown.
   4. No r= and public key is defined as empty or "revoked"
      Then it is revoked.
   5. No r= and the public keys is defined as /something/?
      Let the key try to validate the signature!
   *****/
  if (Revoke && SigDate)
    {
    int r,s;
    for(r=s=0; Revoke[r] && SigDate[s]; r++)
      {
      if (!isdigit(Revoke[r])) { continue; } // only watch dates
      if (!isdigit(SigDate[s])) { IsInvalid=true; break; } // invalid == revoked
      if (Revoke[r] < SigDate[s]) { IsInvalid=true; break; }
      if (Revoke[r] > SigDate[s]) { break; } // signature is older!
      s++;
      }
    if (!Revoke[r]) { IsInvalid=true; } // if it made it all the way, then revoke
    // If revoked finished early, then it's not revoked!
    }
  else if (Revoke) { IsInvalid=true; }
  else if (!Public) { ; } // no public defined means cannot verify
  else if (!Public[0]) { IsInvalid=true; } // revoked
  else if (!strcasecmp(Public,"revoke")) { IsInvalid=true; } // revoked

  if (IsInvalid)
    {
    Rec = SealSetText(Rec,"@error","public key revoked");
    }

  return(Rec);
} /* SealValidateRevoke() */

/********************************************************
 SealValidateSig(): Given seal record with DNS results,
 and decoded binary signature, see if it validates!!!
 This is only called if SealValidateDecodeParts() and
 SealValidateRevoke() worked (no '@error').
 Returns: Errors are detailed in '@error'
 ********************************************************/
sealfield *	SealValidateSig	(sealfield *Rec)
{
  const EVP_MD* (*mdf)(void);
  EVP_PKEY *PubKey=NULL;
  EVP_PKEY_CTX *PubKeyCtx=NULL;
  char *keyalg, *digestalg;
  sealfield *sigbin, *digestbin, *pubkey;
  unsigned long e;

  /*****
   If you're calling this function, then we have:
   '@sigbin' = binary signature
   '@digest' = binary digest
   '@publicbin' = binary public key
   'ka' = key algorthtm
   And we know the record is not revoked.

   Use the public key with the key algorith to decode the signature.
   It should match the digest.
     decode_ka(publicbin,sigbin) == digest
   *****/

  digestalg = SealGetText(Rec,"da"); // SEAL's 'da' parameter
  if (!strcmp(digestalg,"sha224")) { mdf = EVP_sha224; }
  else if (!strcmp(digestalg,"sha256")) { mdf = EVP_sha256; }
  else if (!strcmp(digestalg,"sha384")) { mdf = EVP_sha384; }
  else if (!strcmp(digestalg,"sha512")) { mdf = EVP_sha512; }
  else
	{
	fprintf(stderr,"ERROR: Unsupported digest algorithm (da=%s).\n",digestalg);
	exit(1);
	}

  // Prepare the public key
  pubkey = SealSearch(Rec,"@publicbin");
  if (!pubkey) // should never happen
    {
    Rec = SealSetText(Rec,"@error","no public key found");
    goto Done;
    }

  keyalg = SealGetText(Rec,"ka");
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

  digestbin = SealSearch(Rec,"@digest");
  if (!digestbin) // should never happen
    {
    Rec = SealSetText(Rec,"@error","no digest found");
    goto Done;
    }

  // Load public key into EVP_PKEY structure
  {
  /* Use BIO to import the data */
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
	fprintf(stderr,"Unable to create validation context.\n");
	e = ERR_get_error();
	Rec = SealAddText(Rec,"@error"," (");
	Rec = SealAddText(Rec,"@error",ERR_lib_error_string(e));
	Rec = SealAddText(Rec,"@error",": ");
	Rec = SealAddText(Rec,"@error",ERR_reason_error_string(e));
	Rec = SealAddText(Rec,"@error",")");
	exit(1);
	}
  if (EVP_PKEY_verify_init(PubKeyCtx) != 1)
	{
	fprintf(stderr,"Unable to initialize validation context.\n");
	e = ERR_get_error();
	Rec = SealAddText(Rec,"@error"," (");
	Rec = SealAddText(Rec,"@error",ERR_lib_error_string(e));
	Rec = SealAddText(Rec,"@error",": ");
	Rec = SealAddText(Rec,"@error",ERR_reason_error_string(e));
	Rec = SealAddText(Rec,"@error",")");
	exit(1);
	}

  // RSA needs padding
  if (!strcmp(keyalg,"rsa"))
    {
    if (EVP_PKEY_CTX_set_rsa_padding(PubKeyCtx, RSA_PKCS1_PADDING) != 1)
	{
	fprintf(stderr,"Unable to initialize RSA validation.\n");
	e = ERR_get_error();
	Rec = SealAddText(Rec,"@error"," (");
	Rec = SealAddText(Rec,"@error",ERR_lib_error_string(e));
	Rec = SealAddText(Rec,"@error",": ");
	Rec = SealAddText(Rec,"@error",ERR_reason_error_string(e));
	Rec = SealAddText(Rec,"@error",")");
	exit(1);
	}
    } // setup rsa padding

  if (EVP_PKEY_CTX_set_signature_md(PubKeyCtx, mdf()) != 1)
	{
	fprintf(stderr,"Unable to set digest for validation.\n");
	e = ERR_get_error();
	Rec = SealAddText(Rec,"@error"," (");
	Rec = SealAddText(Rec,"@error",ERR_lib_error_string(e));
	Rec = SealAddText(Rec,"@error",": ");
	Rec = SealAddText(Rec,"@error",ERR_reason_error_string(e));
	Rec = SealAddText(Rec,"@error",")");
	exit(1);
	}

  // Check the signature!
  sigbin = SealSearch(Rec,"@sigbin");
  digestbin = SealSearch(Rec,"@digest");
  if (EVP_PKEY_verify(PubKeyCtx, sigbin->Value, sigbin->ValueLen, digestbin->Value, digestbin->ValueLen) != 1)
	{
	Rec = SealSetText(Rec,"@error","signature mismatch");
	}

Done:
  // Free structures when done.
  if (PubKeyCtx) { EVP_PKEY_CTX_free(PubKeyCtx); }
  if (PubKey) { EVP_PKEY_free(PubKey); }
  return(Rec);
} /* SealValidateSig() */

/********************************************************
 SealVerify(): Given seal record, see if it validates.
 Generates output text!
 ********************************************************/
sealfield *	SealVerify	(sealfield *Rec, mmapfile *Mmap)
{
  char *ErrorMsg;
  long signum; // signature number
  if (!Rec) { return(Rec); }

  /*****
   Signature numbering begins a "1".
   If it's less than 1, then no signature was found.
   If it's 1, then check if it covers the start of the file.
   *****/
  signum = SealGetIindex(Rec,"@s",2);
  if (signum < 1) // should never happen
    {
    printf("WARNING: Invalid SEAL record count (%ld).\n",signum);
    return(Rec);
    }

  /* Compute current digest */
  ErrorMsg = SealGetText(Rec,"@error");

  // Check for prepending: signatures should cover start of file
  if (signum == 1)
    {
    if (!strchr(SealGetText(Rec,"b"),'F'))
	{
	printf("WARNING: SEAL record #%ld does not cover the start of file. Vulnerable to prepending attacks.\n",signum);
	}
    }
  else // if (signum > 1)
    {
    if (!strchr(SealGetText(Rec,"b"),'F') && !strchr(SealGetText(Rec,"b"),'P'))
	{
	printf("WARNING: SEAL record #%ld does not cover the previous signature. Vulnerable to insertion attacks.\n",signum);
	}
    }

  /* Get public key */
  if (!ErrorMsg)
	{
	Rec = SealGetDNS(Rec);
	ErrorMsg = SealGetText(Rec,"@error");
	}

  /* Decode the encoded components */
  if (!ErrorMsg)
	{
	Rec = SealValidateDecodeParts(Rec);
	ErrorMsg = SealGetText(Rec,"@error");
	}

  /* Compute digests */
  if (!ErrorMsg)
	{
	// @sigdate set by SealValidateDecodeParts
	Rec = SealDigest(Rec,Mmap);
	Rec = SealDoubleDigest(Rec); // apply sigdate:userid: as needed
	ErrorMsg = SealGetText(Rec,"@error");
	}

  /* Check revokes */
  if (!ErrorMsg)
	{
	Rec = SealValidateRevoke(Rec);
	ErrorMsg = SealGetText(Rec,"@error");
	}

  /* Check if the decoded digest matches the known digest. */
  if (!ErrorMsg)
	{
	Rec = SealValidateSig(Rec);
	ErrorMsg = SealGetText(Rec,"@error");
	}

  // Report any errors
  if (ErrorMsg)
	{
	printf("SEAL record #%ld is invalid: %s.\n",signum,ErrorMsg);
	}
  else
	{
	char *Txt;

	printf("SEAL record #%ld is valid.\n",signum);

	if (Verbose)
	  {
	  sealfield *range;
	  const size_t *rangeval;
	  int i,MaxRange;
	  range = SealSearch(Rec,"@digestrange");
	  if (range && (range->ValueLen > 0)) // better always be defined!
	    {
	    rangeval = (const size_t*)(range->Value);
	    MaxRange = range->ValueLen / sizeof(size_t);
	    printf(" Signed bytes: ");
	    for(i=0; i < MaxRange; i++)
	      {
	      if (i%2) { printf("-%ld",(long)(rangeval[i])-1); } // end
	      else // start
	        {
		if (i > 0) { printf(", "); }
	        printf("%ld",(long)(rangeval[i]));
		}
	      }
	    printf("\n");
	    }
	  }

	Txt = SealGetText(Rec,"@sigdate");
	if (Txt && Txt[0])
	  {
	  printf(" Signed");
	  printf(" %.4s-%.2s-%.2s",Txt,Txt+4,Txt+6);
	  printf(" at %.2s:%.2s:%.2s",Txt+8,Txt+10,Txt+12);
	  if (Txt[14]=='.') { printf("%s",Txt+14); }
	  printf(" GMT\n");
	  }

	Txt = SealGetText(Rec,"d");
	printf(" Signed");
	printf(" by %s",Txt);

	Txt = SealGetText(Rec,"id");
	if (Txt && Txt[0])
	  {
	  printf(" for %s",Txt);
	  }
	printf("\n");

	Txt = SealGetText(Rec,"copyright");
	if (Txt && Txt[0])
	  {
	  printf(" Copyright: %s\n",Txt);
	  }

	Txt = SealGetText(Rec,"info");
	if (Txt && Txt[0])
	  {
	  printf(" Comment: %s\n",Txt);
	  }
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
  if (Rec) { return(false); }
  if (!SealGetCindex(Rec,"@sflags",1)) // signatures should cover end of file
	{
	printf("WARNING: SEAL records do not finalize the file. Data may be appended.\n");
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
sealfield *	SealVerifyBlock	(sealfield *Args, size_t BlockStart, size_t BlockEnd, mmapfile *Mmap)
{
  size_t RecEnd;
  sealfield *Rec=NULL;

  while(BlockStart < BlockEnd) 
    {
    Rec = SealParse(BlockEnd-BlockStart, Mmap->mem+BlockStart, BlockStart, Args);
    if (!Rec) { return(Args); } // Nothing found

    // Found a signature!  Verify the data!
    Rec = SealCopy2(Rec,"@pubkeyfile",Args,"@pubkeyfile");
    Rec = SealVerify(Rec,Mmap);

    // Iterate on remainder
    RecEnd = SealGetIindex(Rec,"@RecEnd",0);
    if (RecEnd <= 0) { RecEnd=1; } // should never happen, but if it does, stop infinite loops
    BlockStart += RecEnd;
 
    // Retain state
    Args = SealCopy2(Args,"@p",Rec,"@p"); // keep previous settings
    Args = SealCopy2(Args,"@s",Rec,"@s"); // keep previous settings
    Args = SealCopy2(Args,"@dnscachelast",Rec,"@dnscachelast"); // store any cached DNS
    Args = SealCopy2(Args,"@public",Rec,"@public"); // store any cached DNS
    Args = SealCopy2(Args,"@publicbin",Rec,"@publicbin"); // store any cached DNS
    Args = SealCopy2(Args,"@sflags",Rec,"@sflags"); // retain sflags

    // Clean up
    SealFree(Rec); Rec=NULL;
    }

  return(Args);
} /* SealVerifyBlock() */

