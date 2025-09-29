/************************************************
 SEAL: implemented in C
 See LICENSE

 Processing src and sidecar settings.
  srca=   :: algorithim to use for encoding/ was used
  srcd=   :: computed digest in srca format
  src=    :: url of original image
  srcf=   :: path to file for calculating the digest

 Lots of conditionals:

  If srcd is set, then calculate the digest for src if available and compare,
    but warn, do not error if they do not match.

  If srcf is present, then load it, compute srcd, and remove the parameter.
  Why? Don't store local filenames.

  If src is a URL file, then load it, compute srcd, and keep the parameter.
  Why? URLs are expected to be public.

  If verifying and known srcd does not match the computed srcd,
  then flag it as a warning, but allow signing to continue!
 ************************************************/
// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

// For curl
#include <curl/curl.h>

// For Base64
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include "seal.hpp"
#include "files.hpp"
#include "seal-parse.hpp"

enum SealSignatureFormat{
  HEX_LOWER,
  HEX_UPPER,
  BASE64,
  BIN
};

const char* SignatureFormats[] = {"HEX_LOWER", "HEX_UPPER", "BASE64", "BIN"};

/**************************************
 SealCurlSrcCallback(): Process URL results.
 This adds all buffer data to a checksum.
 **************************************/
size_t	SealCurlSrcCallback	(void *buffer, size_t size, size_t nmemb, void *parm)
{
  EVP_MD_CTX* ctx64;
  ctx64 = (EVP_MD_CTX*)parm;
  EVP_DigestUpdate(ctx64,buffer,nmemb*size);
  return(size * nmemb);
} /* SealCurlCallback() */

/**************************************
 SealFinalize Digest(): Finalize the Digest
 **************************************/
char*   SealFinalizeDigest(sealfield *Args, EVP_MD_CTX* ctx64, SealSignatureFormat Sf, const EVP_MD* (*mdf)(void)){
    // Finalize digest
  unsigned int mdsize;
  mdsize = EVP_MD_size(mdf()); // digest size
  Args = SealAlloc(Args,"@srcdCalc",mdsize,'b'); // binary digest
  EVP_DigestFinal(ctx64,SealSearch(Args,"@srcdCalc")->Value,&mdsize); // store the digest
  EVP_MD_CTX_free(ctx64);
  // Re-encode digest from binary to expected srca format.
  switch(Sf){
    case BIN:
      break; // already binary
    case HEX_UPPER:
      SealHexEncode(SealSearch(Args,"@srcdCalc"), true);
      break;
    case HEX_LOWER:
      SealHexEncode(SealSearch(Args,"@srcdCalc"), false);
      break;
    case BASE64:
      SealBase64Encode(SealSearch(Args,"@srcdCalc"));
      break;
    default:
      fprintf(stderr, "ERROR: unsupported Seal Signature Format can not be encoded (%s)\n", SignatureFormats[Sf]);
      exit(0x80);
  }

   return SealGetText(Args,"@srcdCalc");
} /* SealFinalizeDigest() */

/**************************************
 SealGetDigestFromFile(): Get the digest
 from the provided file, and remove srcf
 as a parameter since it should not be 
 saved.
 **************************************/
char*	SealGetDigestFromFile	(sealfield *Args, EVP_MD_CTX* ctx64, SealSignatureFormat srcaSf, const EVP_MD* (*mdf)(void))
{
    char *srcf = SealGetText(Args, "srcf");
    if (!srcf) return NULL;

    FILE *fp = fopen(srcf, "rb");
    if (!fp) {
        fprintf(stderr, "ERROR: could not open src file (%s)\n", srcf);
        exit(0x80);
    }

    byte buffer[4096];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        EVP_DigestUpdate(ctx64, buffer, bytesRead);
    }

    if (ferror(fp)) {
        fprintf(stderr, "ERROR: failed while reading src file (%s)\n", srcf);
        fclose(fp);
        exit(0x80);
    }

    fclose(fp);
    return SealFinalizeDigest(Args, ctx64, srcaSf, mdf);
} /* SealGetDigestFromFile() */

/**************************************
 SealGetDigestFromURL(): Call the src URL 
 and calculate the Digest for the given algorthim
 **************************************/
char*	SealGetDigestFromURL	(sealfield *Args, EVP_MD_CTX* ctx64, SealSignatureFormat srcaSf, const EVP_MD* (*mdf)(void))
{
  sealfield *vf;
  CURL *ch; // curl handle
  CURLcode crc; // curl return code
  char errbuf[CURL_ERROR_SIZE];
  crc = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (crc != CURLE_OK)
    {
    fprintf(stderr," ERROR: Failed to initialize curl. Aborting.\n");
    exit(0x80);
    }

  ch = curl_easy_init();
  if (!ch)
    {
    fprintf(stderr," ERROR: Failed to initialize curl handle. Aborting.\n");
    exit(0x80);
    }

  // Ignore TLS cerification?
  if (SealSearch(Args,"cert-insecure")) { curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 0L); }
  else { curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 1L); }

  // In Cygwin, curl tries to find a cert in /etc, which doesn't exist.
  // Therefore, include our own cacert from https://curl.se/docs/caextract.html
  vf = SealSearch(Args,"cacert");
  if (vf) { curl_easy_setopt(ch, CURLOPT_CAINFO, vf->Value); }

  // Set retrieval parameters
  curl_easy_setopt(ch, CURLOPT_URL, SealGetText(Args,"src")); // set the URL
  curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, SealCurlSrcCallback);
  curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void*)ctx64); // callback gets pointer to open digest
  memset(errbuf,0,CURL_ERROR_SIZE);
  curl_easy_setopt(ch, CURLOPT_ERRORBUFFER, errbuf);
  curl_easy_setopt(ch, CURLOPT_CONNECTTIMEOUT, 20); // 20 seconds to connect
  curl_easy_setopt(ch, CURLOPT_TIMEOUT, 60); // 60 seconds to transfer data

  // Do the request!
  crc = curl_easy_perform(ch);
  curl_easy_cleanup(ch);

  // Clean up
  curl_global_cleanup();
  if (crc != CURLE_OK)
    {
    fprintf(stderr," ERROR: Unable to access src (%s), curl[%d]: %s\n", SealGetText(Args,"src"), crc,errbuf[0] ? errbuf : "unknown");
    exit(0x80);
    }
  return SealFinalizeDigest(Args, ctx64, srcaSf, mdf);
} /* SealGetDigestFromURL() */

/**************************************
 SealProcessSrca(): Split up srca into the
 algorithim and signature format to use
 **************************************/
void	SealProcessSrca	(char* srca, const EVP_MD* (**mdf)(void), SealSignatureFormat* Sf)
{
  // Process srca
  char* srcaCopy = strdup(srca);
  char* srcaDa = strtok(srcaCopy, ":");
  char* srcaSf = strtok(NULL, ":");
  if (!strcmp(srcaDa,"sha224")) { *mdf = EVP_sha224; }
  else if (!strcmp(srcaDa,"sha256")) { *mdf = EVP_sha256; }
  else if (!strcmp(srcaDa,"sha384")) { *mdf = EVP_sha384; }
  else if (!strcmp(srcaDa,"sha512")) { *mdf = EVP_sha512; }
  else
    {
    free(srcaCopy);
    fprintf(stderr, "ERROR: unknown srca algorithm (%s)\n", srcaDa);
    exit(0x80);
    }

  if (!strcmp(srcaSf,"base64")) { *Sf = BASE64; }
  else if (!strcmp(srcaSf,"hex")) { *Sf = HEX_LOWER; }
  else if (!strcmp(srcaSf,"HEX")) { *Sf = HEX_UPPER; }
  else if (!strcmp(srcaSf,"bin")) { *Sf = BIN; }
  else // unsupported
    {
    free(srcaCopy);
    fprintf(stderr, "ERROR: unknown signature format for srca (%s)\n", srcaSf);
    exit(0x80);
    }

  free(srcaCopy);
} /* SealProcessSrca() */

/**************************************
 SealCheckOrSetSrcd(): Checks the digest,
 outputs if it is valid or not, and sets
 the digest if it is not set.
 **************************************/
sealfield * SealCheckOrSetSrcd(sealfield *Args, char *srcd, char *srcdCalc, char *srcRef, bool IsVerbose){
  if (srcd && srcdCalc)
    {
    if (strcmp(srcd, srcdCalc) != 0)
      {
      printf("WARNING: srcd does not match the digest calculated from %s\n", srcRef);
      if(IsVerbose)
        {
        printf("srcd provided:    %s\n", srcd);
        printf("srcd calculated:  %s\n", srcdCalc);
        }
      }
    else
      {
      printf("INFO: Digest Calculated from %s matched the provided digest\n", srcRef);
      }
    }
  else if (srcdCalc && !srcd)
    {
    Args = SealSetText(Args, "srcd", srcdCalc);
    }
  return Args;
} /* SealCheckOrSetSrcd() */


/**************************************
 SealSrcGet(): Get a src record and validate the record at the src 
 and the srcd.
 Currently only supporting url srcs.
 Returns: updated Args
 **************************************/
sealfield *	SealSrcGet	(sealfield *Args, bool IsVerbose)
{
  const EVP_MD* (*mdf)(void);
  char *src,*srcd,*srca, *srcf;
  SealSignatureFormat sf;

  // Get the three main values for this part
  srca = SealGetText(Args,"srca"); 
  srcd = SealGetText(Args,"srcd");
  src = SealGetText(Args,"src");
  srcf = SealGetText(Args,"srcf");

  // Validate the input

  if (!srcd && !src && !srcf) { 
    return(Args); 
  } // nothing to do

  // Split up srca so it can be used where needed
  SealProcessSrca(srca, &mdf, &sf);

  EVP_MD_CTX* ctx64 = EVP_MD_CTX_new();
  EVP_DigestInit(ctx64, mdf());
  char* srcdCalc;
  // Compute the srcd
  if(srcf)
    { 
    srcdCalc = SealGetDigestFromFile(Args, ctx64, sf, mdf); 
    Args = SealCheckOrSetSrcd(Args, srcd, srcdCalc, srcf, IsVerbose);
    Args = SealDel(Args, "srcf");
    }
  else if (src && (strncasecmp(src,"http://",7) == 0 || strncasecmp(src,"https://",8) == 0)) // it's a URL!
    {
    srcdCalc = SealGetDigestFromURL(Args, ctx64, sf, mdf);
    Args = SealCheckOrSetSrcd(Args, srcd, srcdCalc, src, IsVerbose);
    }
  else
    {
    fprintf(stderr,"ERROR: unknown src format (%s)\n", src);
    EVP_MD_CTX_free(ctx64);
    exit(0x80);
    }

  return(Args);
} /* SealSrcGet() */

/**************************************
 SealSrcVerify(): Process a src record!
 Populate and validate srcd.
 Returns: true on success, false on error.
 **************************************/
void	SealSrcVerify	(sealfield *Args)
{ 
  char *srcd, *src, *srca;
  const EVP_MD* (*mdf)(void);
  SealSignatureFormat sf;
  char *srcdCalc;

  srcd = SealGetText(Args,"srcd");
  src = SealGetText(Args,"src");
  srca = SealGetText(Args,"srca");

  // If there's nothing to verify, just return.
  if (!srcd || !src || !srca)
    {
    return;
    }

  // Process srca to get the algorithm and format
  SealProcessSrca(srca, &mdf, &sf);

  EVP_MD_CTX* ctx64 = EVP_MD_CTX_new();
  EVP_DigestInit(ctx64, mdf());

  // Compute the digest from the src URL
  if (strncasecmp(src,"http://",7) == 0 || strncasecmp(src,"https://",8) == 0)
    {
    srcdCalc = SealGetDigestFromURL(Args, ctx64, sf, mdf);
    }
  else
    {
    // Currently only URL src is supported for verification.
    // Local files are not stored in the record.
    EVP_MD_CTX_free(ctx64);
    return;
    }

  // Compare the provided srcd with the one we just calculated
  if (srcd && srcdCalc)
    {
    if (strcmp(srcd, srcdCalc) != 0)
      {
      printf("  WARNING: srcd value does not match calculated digest for src\n");
      printf("    srcd: %s\n", srcd);
      printf("    calc: %s\n", srcdCalc);
      }
    }
} /* SealSrcVerify() */
