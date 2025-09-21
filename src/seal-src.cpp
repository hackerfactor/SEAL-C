/************************************************
 SEAL: implemented in C
 See LICENSE

 Processing src and sidecar settings.
  srca=   :: essential: encoding info
  srcd=   :: computed digest in srca format
  src=    :: path/url to the sidecar file

 Lots of conditionals:

  If srcd is set, then src is ignored.
  Otherwise, src is used to set srcd.

  If src is a local file, then load it, compute srcd, and remove the parameter.
  Why? Don't store local filenames.

  If src is a URL file, then load it, compute srcd, and keep the parameter.
  Why? URLs are expected to be public.
 
  If signing and 'sidecar' is set, then set the output filename to:
    argv[optind] + ".seal"

  If verifying and known srcd does not match the computed srcd,
  then flag it as an error!
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

/**************************************
 SealCurlSrcCallback(): Process URL results.
 This adds all buffer data to a checksum.
 **************************************/
size_t	SealCurlSrcCallback	(void *buffer, size_t size, size_t nmemb, void *parm)
{
  EVP_MD_CTX* ctx64;
  ctx64 = (EVP_MD_CTX*)parm;
  EVP_DigestUpdate(ctx64,buffer,nmemb*size);
  return(nmemb*size);
} /* SealCurlCallback() */

/**************************************
 SealSrcGet(): Get a src record and validate the record at the src 
 and the srcd.
 Currently only supporting url srcs.
 Returns: updated Args
 **************************************/
sealfield *	SealSrcGet	(sealfield *Args)
{
  const EVP_MD* (*mdf)(void);
  char *src,*srcd;
  char *srca;
  sealfield *vf;

  // Get the three main values for this part
  srca = SealGetText(Args,"srca"); 
  srcd = SealGetText(Args,"srcd"); // must be defined if srca is
  src = SealGetText(Args,"src");

  // Validate the input

  if (!srcd && !src) { return(Args); } // nothing to do
  if (!srcd && srca) //the algorithim is present, but not the digest
    {
      Args = SealSetText(Args,"@error","undefined srca");
      return(Args);
    }

  // Process srca
  if(!srca){ //Set it to the default if not specified
    srca = SealGetText(Args, "srcaDefault");
  }

  char* srcaCopy = strdup(srca);
  char* srcaDa = strtok(srcaCopy, ":");
  char* srcaSf = strtok(NULL, ":");

  if (!strcmp(srcaDa,"sha224")) { mdf = EVP_sha224; }
  else if (!strcmp(srcaDa,"sha256")) { mdf = EVP_sha256; }
  else if (!strcmp(srcaDa,"sha384")) { mdf = EVP_sha384; }
  else if (!strcmp(srcaDa,"sha512")) { mdf = EVP_sha512; }
  else
    {
      Args = SealSetText(Args,"@error","unknown srca format (");
      Args = SealAddText(Args,"@error",srca);
      Args = SealAddText(Args,"@error",")");
      return(Args);
}
  EVP_MD_CTX* ctx64 = EVP_MD_CTX_new();
  EVP_DigestInit(ctx64, mdf());

  // Compute the srcd
   if (src && (strncasecmp(src,"http://",7) == 0 || strncasecmp(src,"https://",8) == 0)) // it's a URL!
    {
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
	fprintf(stderr," ERROR: curl[%d]: %s\n",crc,errbuf[0] ? errbuf : "unknown");
	exit(0x80);
	}
    }
  else if (SealIsFile(src)) // src is a file!
    {
      fprintf(stderr," ERROR: Local src files are not currently supported (%s)",src);
      exit(0x80);
    }
  else {
    printf("COULD NOT IDENTIFY FILE TYPE\n");
    Args = SealSetText(Args,"@error","unknown src format (");
    Args = SealAddText(Args,"@error",src);
    Args = SealAddText(Args,"@error",")");
    EVP_MD_CTX_free(ctx64);
    return(Args);
  }

printf("Curl Done\n");

  // Finalize digest
  unsigned int mdsize;
  mdsize = EVP_MD_size(mdf()); // digest size
  Args = SealAlloc(Args,"@srcdCalc",mdsize,'b'); // binary digest
  EVP_DigestFinal(ctx64,SealSearch(Args,"@srcdCalc")->Value,&mdsize); // store the digest
  EVP_MD_CTX_free(ctx64);

  // Re-encode digest from binary to expected srca format.
  // Currently, only supports base64.
  if (!strcmp(srcaSf,"base64")) { SealBase64Decode(SealSearch(Args,"@srcdCalc")); }
  else if (!strcmp(srcaSf,"hex")) { SealHexDecode(SealSearch(Args,"@srcdCalc")); }
  else if (!strcmp(srcaSf,"bin")) { ; } // already binary
  else // unsupported
	{
	Args = SealSetText(Args,"@error","unknown srca format (");
	Args = SealAddText(Args,"@error",srca);
	Args = SealAddText(Args,"@error",")");
	return(Args);
	}

  // Compare calculated digest to the expected

  return(Args);
} /* SealSrcGet() */

/**************************************
 SealSrcVerify(): Process a src record!
 Populate and validate srcd.
 Returns: true on success, false on error.
 **************************************/
bool	SealSrcVerify	(sealfield *Args, const char *Fname)
{
  return(true);
} /* SealSrcVerify() */


/**************************************
 SealHasRef(): Checks if there is src data.
 Returns: true if srcd or src is present.
 **************************************/
bool    SealHasRef (sealfield *Args)
{
        return SealGetText(Args,"srcd") || SealGetText(Args,"src");
}

