/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling DNS requests and caching.

 This speeds up DNS and permits looping over TXT results.
 It tracks case-insensitive domain lookups.

 NOTE: Caching only caches TXT records.
 NOTE: Caching does NOT check for acceptable parameters.
 NOTE: Caching does NOT check for revocation!

 Why? Because revocation is date sensitive and
 parameter requirements vary by caller.
 The caller must check for these requirements.
 ************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#include "seal.hpp"
#include "sign.hpp"
#include "files.hpp"
#include "seal-parse.hpp"
#include "ns_parse.hpp"

struct dnscache
  {
  char *Domain;
  char *TXT;
  sealfield *Rec;
  struct dnscache *Next;
  };
typedef struct dnscache dnscache;
dnscache *DNSCache=NULL;

/************************************************
 SealDNSFlushCache(): Free any cached DNS records.
 (Mostly for debugging and house-keeping.)
 ************************************************/
void	SealDNSFlushCache	()
{
  dnscache *d;
  while(DNSCache)
    {
    d = DNSCache;
    if (d->Domain) { free(d->Domain); }
    if (d->TXT) { free(d->TXT); }
    SealFree(d->Rec);
    DNSCache = d->Next;
    free(d);
    }
} /* SealDNSFlushCache() */

/************************************************
 SealDNSWalk(): Debugging.
 Show all cached DNS records.
 ************************************************/
void	SealDNSWalk	()
{
  dnscache *d;
  for(d=DNSCache; d; d=d->Next)
    {
    printf("DNS Cache [%s] = %s\n",d->Domain,d->TXT);
    }
} /* SealDNSWalk() */

/************************************************
 _SealDNSnet(): Do a network request and cache the results.
 Returns: Number of records created.
 ************************************************/
int	_SealDNSnet	(char *Domain)
{
  dnscache *dnew;
  sealfield *vBuf=NULL;
  int InsertCount=0;
  unsigned char Buffer[16384]; // permit 16K buffer for DNS reply (should be overkill)
  const char *s;
  int Txti; // DNS unparsed (input) TXT as offset into Buffer
  int size;
  ns_msg nsMsg;
  ns_rr rr; // dns response record
  struct __res_state dnsstate;
  int MsgMax, count, c;

  // Idiot checking
  if (!Domain || !Domain[0]) { return(0); }

  // Prepare structures
  memset(&dnsstate, 0, sizeof(dnsstate));
  if (res_ninit(&dnsstate) < 0)
    {
    // Should never happen
    fprintf(stderr," ERROR: Unable to initialize DNS lookup. Aborting.\n");
    exit(0x80);
    }

  // Retrieve DNS request
  memset(&Buffer, 0, 16384);
  MsgMax = res_nquery(&dnsstate, Domain, C_IN, T_TXT, Buffer, 16384-1);

  // Found something!
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
    if (ns_initparse(Buffer, MsgMax, &nsMsg)) { MsgMax=0; goto Done; } // failed?

    // How many ANSWER replies?
    count = ns_msg_count(nsMsg, ns_s_an);
    for(c=0; c < count; c++)
      {
      if (ns_parserr(&nsMsg,ns_s_an,c,&rr)) { continue; } // if failed to parse
      if (ns_rr_type(rr) != ns_t_txt) { continue; } // must be TXT

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

      // Now I have something in vBuf['r']that looks like "<seal DNSstuff />"
      // Check for SEAL record: must contain "seal=" and a version number
      s = SealGetText(vBuf,"r");
      if (strncmp(s+6,"seal=",5) || !isdigit(s[11])) { SealFree(vBuf); vBuf=NULL; continue; }

      // Store the record in the cache!
      dnew = (dnscache*)calloc(sizeof(dnscache),1);

      dnew->Domain = (char*)calloc(strlen(Domain)+2,1); // why +2? I want to ensure a '\0' at end of string.
      strcpy(dnew->Domain,Domain);

      dnew->TXT = (char*)calloc(SealGetSize(vBuf,"r")+1,1); // why +1? I want to ensure a '\0' at end of string.
      strcpy(dnew->TXT,s);

      dnew->Rec = SealParse(SealGetSize(vBuf,"r"),(byte*)SealGetText(vBuf,"r"),0,NULL);

      // If the ka is defined but unknown, then ignore this TXT record.
      s = SealGetText(dnew->Rec,"ka");
      if (s && (CheckKeyAlgorithm(s) == 0))
        {
	// Unknown! Don't cache it.
	free(dnew->Domain);
	free(dnew->TXT);
	SealFree(dnew->Rec);
	free(dnew);
	continue;
	}

      // Decode any known-binary fields
      if (SealSearch(dnew->Rec,"p"))
        {
	dnew->Rec = SealCopy(dnew->Rec,"@p-bin","p");
	SealBase64Decode(SealSearch(dnew->Rec,"@p-bin"));
	}
      if (SealSearch(dnew->Rec,"pkd"))
        {
	dnew->Rec = SealCopy(dnew->Rec,"@pkd-bin","pkd");
	SealBase64Decode(SealSearch(dnew->Rec,"@pkd-bin"));
	}

      // Insert record
      dnew->Next = DNSCache;
      DNSCache = dnew;
      InsertCount++;

      SealFree(vBuf); vBuf=NULL;
      } // foreach dns record
    } // if dns reply

Done:
  if (MsgMax <= 0) // found nothing!
    {
    // Set a marker so I don't look up the same domain twice.
    dnew = (dnscache*)calloc(sizeof(dnscache),1);
    dnew->Domain = (char*)calloc(strlen(Domain)+2,1); // why +2? I want to ensure a '\0' at end of string.
    strcpy(dnew->Domain,Domain);
    // Insert record
    dnew->Next = DNSCache;
    DNSCache = dnew;
    // Don't count this as a new insert
    }

  if (vBuf) { SealFree(vBuf); vBuf=NULL; }
  return(InsertCount);
} /* _SealDNSnet() */

/************************************************
 SealDNSLoadFile(): Load a DNS record from a file.
 NOTE: No associated domain name! Use as a default record.
 ************************************************/
void	SealDNSLoadFile	(const char *Fname)
{
  mmapfile *Mmap;
  dnscache *dnew;
  sealfield *vBuf=NULL;

  if (!Fname || !Fname[0]) { return; }
  Mmap = MmapFile(Fname,PROT_READ);
  if (!Mmap || // bad/missing file
      (Mmap->memsize < 10) || (Mmap->memsize > 4096)) // file too big or too small
    {
    MmapFree(Mmap);
    return;
    }

  vBuf = SealSetText(vBuf,"r","<seal ");
  vBuf = SealAddBin(vBuf,"r",Mmap->memsize,Mmap->mem);
  vBuf = SealAddText(vBuf,"r"," />");

  // Store the record in the cache!
  dnew = (dnscache*)calloc(sizeof(dnscache),1);

  dnew->Rec = SealParse(SealGetSize(vBuf,"r"),(byte*)SealGetText(vBuf,"r"),0,NULL);
  if (!dnew->Rec || !SealSearch(dnew->Rec,"seal")) // failed to parse?
	{
	SealFree(dnew->Rec);
	free(dnew);
	MmapFree(Mmap);
	SealFree(vBuf);
	return;
	}

  dnew->Domain = (char*)calloc(10,1); // I want to ensure a '\0' at end of string.
  strcpy(dnew->Domain,"@default");

  dnew->TXT = (char*)calloc(SealGetSize(vBuf,"r")+1,1); // why +1? I want to ensure a '\0' at end of string.
  strcpy(dnew->TXT,SealGetText(vBuf,"r"));

  // Decode any known-binary fields
  if (SealSearch(dnew->Rec,"p"))
	{
	dnew->Rec = SealCopy(dnew->Rec,"@p-bin","p");
	SealBase64Decode(SealSearch(dnew->Rec,"@p-bin"));
	}
  if (SealSearch(dnew->Rec,"pkd"))
	{
	dnew->Rec = SealCopy(dnew->Rec,"@pkd-bin","pkd");
	SealBase64Decode(SealSearch(dnew->Rec,"@pkd-bin"));
	}

  // Insert record
  dnew->Next = DNSCache;
  DNSCache = dnew;

  MmapFree(Mmap);
  SealFree(vBuf);
} /* SealDNSLoadFile() */

/************************************************
 SealDNSGet(): Retrieve a DNS TXT record for the domain.
 This parses the fields into a sealfield set.
   Args: Must define "d" for the domain to retrieve.
   DNSRecordNumber: Which record to return? 0 is the first record.
 It also decodes any keys or digests into binary.
 Returns: Set or NULL if no DNS record.
 WARNING: Caller must NEVER CHANGE the returned structure!
 ************************************************/
sealfield *	SealDNSGet	(sealfield *Args, int DNSRecordNumber)
{
  dnscache *d;
  char *Domain;
  dnscache *DefaultDomain=0;

  // What domain do I want to get?
  if (DNSRecordNumber < 0) { return(NULL); } // impossible!
  Domain = SealGetText(Args,"d"); // must be defined
  if (!Domain) { return(NULL); }

  // See if that domain exists in the cache.
  for(d=DNSCache; d; d=d->Next)
    {
    if (!d->Domain) { continue; } // should never happen
    if (!DefaultDomain && !strcmp("@default",d->Domain)) { DefaultDomain = d; }
    if (!strcasecmp(Domain,d->Domain)) // Found it!
      {
      if (!d->TXT) { return(NULL); } // Denotes a lookup that failed to find records.
      break;
      }
    }

  // Not exist in cache!

  // Abort if there is no network.
  if (SealSearch(Args,"no-net")) { return(NULL); }

  // Go get it!
  if (!d && !DefaultDomain)
    {
    if (!_SealDNSnet(Domain)) { return(NULL); }
    // Now go find it!
    for(d=DNSCache; d; d=d->Next)
      {
      if (!d->Domain) { continue; } // should never happen
      if (!strcasecmp(Domain,d->Domain)) // Found it!
        {
        if (!d->Rec) { return(NULL); } // Denotes a lookup that failed to find records.
        break;
        }
      }
    }
  else if (!d && DefaultDomain) { d = DefaultDomain; } // default exists? Use it!

  // d is now pointing to the first match in the cache.
  char *dnsname = d->Domain; // either passed in domain, or "@default"
  for( ; d; d=d->Next)
    {
    if (!d->Domain) { continue; } // should never happen
    if (!d->Rec) { return(NULL); } // only happens with a failed lookup
    if (strcasecmp(d->Domain,dnsname)) { continue; } // wrong domain name
    if (DNSRecordNumber > 0) { DNSRecordNumber--; continue; }
    else { return(d->Rec); } // Found the record!
    }

  // No more records!
  return(NULL);
} /* SealDNSGet() */

/************************************************
 SealDNSCount(): How many DNS records are associated with this domain?
 ************************************************/
int	SealDNSCount	(sealfield *Args)
{
  char *Domain;
  dnscache *d;
  int count=0, defaultcount=0;

  Domain = SealGetText(Args,"d"); // must be defined
  if (!Domain) { return(0); }

  // How many DNS records have been received for this domain?
  if (!SealDNSGet(Args,0)) { return(0); } // Get records if they are not already cached.

  // Count the number of matches!
  for(d=DNSCache; d; d=d->Next)
    {
    if (!d->Domain) { continue; } // should never happen
    if (!d->TXT) { continue; } // Could happen if a DNS lookup occurred but no results found
    /*****
     Performance note:
     If there are tens of thousands of cached records, then this could be slow.
     (Very unlikely.)
     But in that case, maybe change the structure from a linked list to an rb-tree.
     *****/
    if (!strcasecmp(Domain,d->Domain)) { count++; } // found one!
    else if (!strcmp("@default",d->Domain)) { defaultcount++; } // count defaults
    }

  if (!count) { return(defaultcount); } // if none found, count the defaults
  return(count);
} /* SealDNSCount() */

