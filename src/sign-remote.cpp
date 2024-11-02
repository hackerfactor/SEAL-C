/************************************************
 SEAL: Code to handle curl requests.
 See LICENSE

 curl is used to access a remote signer.
 (The "-S" parameter.)

 curl has two modes:
   Easy is synchronous and blocking.
   The other is multithreaded and non-blocking.
 For this code, use easy!
 ************************************************/

#include <curl/curl.h>
#include <string.h> // memset
#include "seal.hpp"
#include "sign.hpp"
#include "json.hpp"

/********************************************************
 SealIsURL(): Is the signer local (false) or remote (true)?
 ********************************************************/
bool	SealIsURL	(sealfield *Args)
{
  char *Str;
  if (!Args) { return(false); } // must be defined
  Str = SealGetText(Args,"apiurl"); // must be defined
  if (!Str) { return(false); }
  if (strncasecmp(Str,"http://",7) && strncasecmp(Str,"https://",8)) { return(false); }
  return(true);
} /* SealIsURL() */

/********************************************************
 SealCurlCallback(): Receive data from curl!
 ********************************************************/
size_t	SealCurlCallback	(void *buffer, size_t size, size_t nmemb, void *parm)
{
  sealfield *Args;
  Args = (sealfield *)parm;
  SealAddBin(Args,"@curldata",nmemb*size,(byte*)buffer);
  return(nmemb*size);
} /* SealCurlCallback() */

/********************************************************
 SealSignURL(): Sign using a web request.
 There are two modes:
   If Args['@digest'] is not set, then returns amount of space to allocate (sigsize).
   If Args['@digest'] is set, then do the signature (signature).
 Returns: Args on success, aborts on failure.
  Sets the seal field with the results.
    "@sigsize" = signature length as uint32_t
    "@signature" = computed signature (always set, but may be empty)
 ********************************************************/
sealfield *	SealSignURL	(sealfield *Args)
{
  sealfield *vf;
  char *Str;
  CURL *ch; // curl handle
  CURLcode crc; // curl return code
  char errbuf[CURL_ERROR_SIZE];

  // Make sure there's a known API URL!
  if (!SealIsURL(Args)) // Caller should make sure this never happens
    {
    fprintf(stderr,"ERROR: apiurl does not begin with http:// or https://. Aborting.\n");
    exit(1);
    }

  // Clear any previous results
  Args = SealDel(Args,"@sigsize");
  Args = SealDel(Args,"@signature");

  // Prepare curl
  crc = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (crc != CURLE_OK)
    {
    fprintf(stderr,"ERROR: Failed to initialize curl. Aborting.\n");
    exit(1);
    }

  ch = curl_easy_init();
  if (!ch)
    {
    fprintf(stderr,"ERROR: Failed to initialize curl handle. Aborting.\n");
    exit(1);
    }

  // Set retrieval parameters
  Str = SealGetText(Args,"apiurl");
  curl_easy_setopt(ch, CURLOPT_URL, Str); // set the URL
  curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, SealCurlCallback);
  Args = SealSetText(Args,"@curldata","");
  curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void*)Args);
  memset(errbuf,0,CURL_ERROR_SIZE);
  curl_easy_setopt(ch, CURLOPT_ERRORBUFFER, errbuf);
  curl_easy_setopt(ch, CURLOPT_CONNECTTIMEOUT, 20); // 20 seconds to connect
  curl_easy_setopt(ch, CURLOPT_TIMEOUT, 10); // 10 seconds to transfer data

  // Build the post data
  Args = SealSetText(Args,"@post","seal=1"); // seal version is always 1

  Str = SealGetText(Args,"id"); // add id
  if (Str && Str[0])
    {
    Args = SealAddText(Args,"@post","&id=");
    Args = SealAddText(Args,"@post",Str);
    }

  Str = SealGetText(Args,"apikey"); // add apikey
  if (Str && Str[0])
    {
    Args = SealAddText(Args,"@post","&apikey=");
    Args = SealAddText(Args,"@post",Str);
    }

  Str = SealGetText(Args,"kv"); // add key version
  if (Str && Str[0])
    {
    Args = SealAddText(Args,"@post","&kv=");
    Args = SealAddText(Args,"@post",Str);
    }

  Str = SealGetText(Args,"ka"); // add key algorithm
  if (Str && Str[0])
    {
    Args = SealAddText(Args,"@post","&ka=");
    Args = SealAddText(Args,"@post",Str);
    }

  Str = SealGetText(Args,"sf"); // add signing format
  if (Str && Str[0])
    {
    Args = SealAddText(Args,"@post","&sf=");
    Args = SealAddText(Args,"@post",Str);
    }

  if (Verbose)
    {
    Args = SealAddText(Args,"@post","&verbose=1");
    }

  vf = SealSearch(Args,"@digest");
  if (vf && (vf->ValueLen > 0))
    {
    /*****
     digest is binary, but we need it in hex.
     *****/
    uint64_t b;
    int n; // nibble
    Str = (char*)calloc(vf->ValueLen*2+4,1); // allocate extra for null padding
    for(b=0; b < vf->ValueLen; b++)
      {
      n=(vf->Value[b] / 0x10);
      if (n < 10) { Str[b*2+0] = '0'+n; }
      else { Str[b*2+0] = 'a'+(n-10); }
      n=(vf->Value[b] % 0x10);
      if (n < 10) { Str[b*2+1] = '0'+n; }
      else { Str[b*2+1] = 'a'+(n-10); }
      }
    // Store hex
    Args = SealAddText(Args,"@post","&digest=");
    Args = SealAddText(Args,"@post",Str);
    free(Str);
    }

  // Set the post data
  Str = SealGetText(Args,"@post");
  //DEBUGPRINT("POST: %s",Str);
  curl_easy_setopt(ch, CURLOPT_POSTFIELDS, Str);

  // Do the request!
  crc = curl_easy_perform(ch);
  curl_easy_cleanup(ch);

  // Clean up
  curl_global_cleanup();
  if (crc != CURLE_OK)
    {
    fprintf(stderr,"ERROR: curl(%d]: %s\n",crc,errbuf[0] ? errbuf : "unknown");
    exit(1);
    }

  /*****
   Check for sigsize and signature!
   NOTE: I should be parsing the result as a JSON, but libjson is overkill.
   Let's go small and just look for the field!
   NOTE: The value may contain "\" to quote the next character.
   *****/
  sealfield *json, *jsonv;
  json = Json2Seal(SealSearch(Args,"@curldata"));
  if (json)
    {
    if (Verbose > 1)
	{
	if (Verbose > 2) { DEBUGWALK("Remote results",json); }
	else
	  {
	  jsonv = SealSearch(json,"double-digest");
	  if (jsonv) { printf("DEBUG Double Digest: %s\n",jsonv->Value); }
	  }
	}
    jsonv = SealSearch(json,"sigsize");
    if (!jsonv) { ; }
    else if (jsonv->Type=='4') { Args = SealSetU32index(Args,"@sigsize",0,((uint32_t*)jsonv->Value)[0]); }
    else if (jsonv->Type=='8') { Args = SealSetU32index(Args,"@sigsize",0,((uint64_t*)jsonv->Value)[0]); }
    else if (jsonv->Type=='c') { Args = SealSetU32index(Args,"@sigsize",0,atol((char*)jsonv->Value)); }

    jsonv = SealSearch(json,"signature");
    if (!jsonv) { ; }
    else if (jsonv->Type=='c') { Args = SealSetTextLen(Args,"@signatureenc",jsonv->ValueLen,(char*)jsonv->Value); }
    SealFree(json);
    }

  return(Args);
} /* SealSignURL() */

