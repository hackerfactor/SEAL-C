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
#include "sign.hpp"

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
  SealEncode(SealSearch(Args, "@srcdCalc"), Sf);

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
        printf("  Source unavailable: %s\n", srcf);
        if(Verbose)
          {
          printf("  ERROR: could not open src file (%s)\n", srcf);
          }
        return NULL;
    }

    byte buffer[4096];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        EVP_DigestUpdate(ctx64, buffer, bytesRead);
    }

    if (ferror(fp))
      {
      printf("  Source unavailable: %s\n", srcf);
      if(Verbose)
        {
        printf("  ERROR: failed while reading src file (%s)\n", srcf);
        }
      fclose(fp);
      return NULL;
      }

    fclose(fp);
    return SealFinalizeDigest(Args, ctx64, srcaSf, mdf);
} /* SealGetDigestFromFile() */

/**************************************
 SealGetDigestFromURL(): Call the src URL 
 and calculate the Digest for the given algorthim
 Returns: digest, or NULL on failure.
 **************************************/
char*	SealGetDigestFromURL	(sealfield *Args, EVP_MD_CTX* ctx64, SealSignatureFormat srcaSf, const EVP_MD* (*mdf)(void))
{
  sealfield *vf;
  CURL *ch; // curl handle
  CURLcode crc; // curl return code
  char * src;
  char errbuf[CURL_ERROR_SIZE];

  if (SealSearch(Args,"no-net")) { return(NULL); }

  src = SealGetText(Args,"src");
  crc = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (crc != CURLE_OK)
    {
    printf("  Source unavailable: %s\n", src);
    if(Verbose)
      {
      printf("  Failed to initialize curl. Aborting.\n");
      } 
    return NULL;
    }

  ch = curl_easy_init();
  if (!ch)
    {
      printf("  Source unavailable: %s\n", src);
      if(Verbose)
      {
      printf("  Failed to initialize curl handle. Aborting.\n");
      } 
    return NULL;
    }

  // Ignore TLS cerification?
  if (SealSearch(Args,"cert-insecure")) { curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 0L); }
  else { curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 1L); }

  // In Cygwin, curl tries to find a cert in /etc, which doesn't exist.
  // Therefore, include our own cacert from https://curl.se/docs/caextract.html
  vf = SealSearch(Args,"cacert");
  if (vf) { curl_easy_setopt(ch, CURLOPT_CAINFO, vf->Value); }

  // Set retrieval parameters
  curl_easy_setopt(ch, CURLOPT_URL, src); // set the URL
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
    printf("  Source unavailable: %s\n", SealGetText(Args,"src"));
    if(Verbose)
      {
      printf("  curl[%d]: %s\n", crc,errbuf[0] ? errbuf : "unknown");
      }
    return NULL;
    }
  return SealFinalizeDigest(Args, ctx64, srcaSf, mdf);
} /* SealGetDigestFromURL() */

/**************************************
 SealProcessSrca(): Split up srca into the
 algorithim and signature format to use
 **************************************/
bool	SealProcessSrca	(char* srca, const EVP_MD* (**mdf)(void), SealSignatureFormat* Sf)
{
  // Process srca
  char* srcaCopy = strdup(srca);
  char* srcaDa = strtok(srcaCopy, ":");
  char* srcaSf = strtok(NULL, ":");
  *mdf = SealGetMdfFromString(srcaDa);
  if (!*mdf)
    {
    free(srcaCopy);
    printf("ERROR: unknown srca algorithm (%s) in %s\n", srcaDa, srca);
    return false;
    }

  *Sf = SealGetSF(srcaSf);
  if (*Sf == INVALID) // SealGetSF returns INVALID for unsupported formats
    {
    printf("ERROR: unknown signature format for srca (%s) in %s\n", srcaSf, srca);
    free(srcaCopy);
    return false;
    }
  free(srcaCopy);
  return true;
} /* SealProcessSrca() */

/**************************************
 SealCheckOrSetSrcd(): Checks the digest,
 outputs if it is valid or not, and sets
 the digest if it is not set.
 **************************************/
sealfield * SealCheckOrSetSrcd(sealfield *Args, char *srcd, char *srcdCalc, char *srcRef)
{
  if (srcd && srcdCalc)
    {
    if (strcmp(srcd, srcdCalc) != 0)
      {
      printf("  Source mismatched: %s\n", srcRef);
      }
    else
      {
      printf("  Source matched: %s \n", srcRef);
      }
    if(Verbose)
      {
      printf("  srcd provided:   %s\n", srcd);
      printf("  srcd calculated: %s\n", srcdCalc);
      }
    }
  else if (srcdCalc && !srcd)
    {
    Args = SealSetText(Args, "srcd", srcdCalc);
    if(Verbose)
      {
      printf("  srcd calculated: %s\n", srcdCalc);
      }
    }
  else
    {
    printf("  Error: Digest could not be generated for %s\n", srcRef);
    exit(0x80);
    }
  return Args;
} /* SealCheckOrSetSrcd() */

/**************************************
 SealSrcGet(): Get a src record and validate the record at the src 
 and the srcd.
 Currently only supporting url srcs.
 Returns: updated Args
 **************************************/
sealfield *	SealSrcGet	(sealfield *Args)
{
  const EVP_MD* (*mdf)(void);
  char *src,*srcd,*srca, *srcf;
  SealSignatureFormat sf;
  bool canProceed;

  // Get the three main values for this part
  srca = SealGetText(Args,"srca"); 
  srcd = SealGetText(Args,"srcd");
  srcf = SealGetText(Args,"srcf");
  src = SealGetText(Args,"src");
  //DEBUGPRINT("srca=%s srcd=%s src=%s srcf=%s",srca,srcd,src,srcf);

  // Validate the input

  // must have either src or srcf
  if (!src && !srcf)
    { 
    return(Args); 
    } // nothing to do

  // Split up srca so it can be used where needed
  canProceed = SealProcessSrca(srca, &mdf, &sf);
  if(!canProceed) // Can not sign with invalid srca
    {
    exit(0x80);
    }

  EVP_MD_CTX* ctx64 = EVP_MD_CTX_new();
  EVP_DigestInit(ctx64, mdf());
  char* srcdCalc;
  // Compute the srcd
  if(srcf)
    { 
    srcdCalc = SealGetDigestFromFile(Args, ctx64, sf, mdf); 
    Args = SealCheckOrSetSrcd(Args, srcd, srcdCalc, srcf);
    }
  else if (src && (!strncasecmp(src,"http://",7) || !strncasecmp(src,"https://",8))) // it's a URL!
    {
    srcdCalc = SealGetDigestFromURL(Args, ctx64, sf, mdf);
    Args = SealCheckOrSetSrcd(Args, srcd, srcdCalc, src);
    }
  else
    {
    printf(" ERROR: unknown src format (%s)\n", src);
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
  char *srcd, *src, *srca, *srcf;
  const EVP_MD* (*mdf)(void);
  SealSignatureFormat sf;
  char *srcdCalc=NULL;

  srca = SealGetText(Args,"srca");
  srcd = SealGetText(Args,"srcd");
  srcf = SealGetText(Args,"srcf");
  src = SealGetText(Args,"src");
  //DEBUGPRINT("srca=%s srcd=%s src=%s srcf=%s",srca,srcd,src,srcf);

  // src must be a web URL
  if (src && strncasecmp(src,"http://",7) && strncasecmp(src,"https://",8))
    {
    // Not http or https
    printf("  Unsupported source: %s\n",src);
    src=NULL;
    }

  // src without srcd cannot be validated
  if (src && !srcd)
    {
    printf("  Unverfied source: %s\n",src);
    return;
    }

  // If there's nothing to verify, just return.
  if (!srcd || !srca) { return; } // needs srcd and srca
  if (!src && !srcf) { return; } // either src or srcf

  // Process srca to get the algorithm and format
  SealProcessSrca(srca, &mdf, &sf);

  EVP_MD_CTX* ctx64 = EVP_MD_CTX_new();
  EVP_DigestInit(ctx64, mdf());

  // Compute the digest from the src URL
  if (srcf) // if user supplied srcf, then use it!
    {
    srcdCalc = SealGetDigestFromFile(Args, ctx64, sf, mdf);
    // What if we have both srcf and src?
    // Check if srcf worked. Otherwise, try src.
    if ((srcdCalc && (strcmp(srcd, srcdCalc) == 0)) || !src) // correct hash or no fallback
      {
      src=srcf;
      }
    else if (src) // wrong hash; if a fallback exists, use it
      {
      // reset checksum; get it from url
      if (!srcdCalc) { EVP_MD_CTX_free(ctx64); }
      ctx64 = EVP_MD_CTX_new();
      EVP_DigestInit(ctx64, mdf());
      srcdCalc = SealGetDigestFromURL(Args, ctx64, sf, mdf);
      }
    }
  else if (src) // no srcf and has src
    {
    srcdCalc = SealGetDigestFromURL(Args, ctx64, sf, mdf);
    }

  if (!srcdCalc)
    {
    // Currently only URL src is supported for verification.
    // Local files are not stored in the record.
    if (Verbose)
      {
      printf(" Source digest: unavailable (%s)\n", src);
      }
    else
      {
      printf(" Source digest: unavailable\n");
      }
    EVP_MD_CTX_free(ctx64);
    return;
    }

  // Compare the provided srcd with the one we just calculated
  if (srcd && srcdCalc)
    {
    if (strcmp(srcd, srcdCalc) != 0)
      {
      printf("  Source mismatch: %s\n",src);
      if (Verbose)
	{
	printf("  srcd provided:   %s\n", srcd);
	printf("  srcd calculated: %s\n", srcdCalc);
	}
      }
    else 
      {
      printf("  Source matched: %s\n", src);
      if (Verbose)
	{
	printf("  Source Digest: %s\n", srcd);
	}
      }
    }
} /* SealSrcVerify() */
