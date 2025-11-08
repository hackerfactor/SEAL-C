/************************************************
 SEAL: implemented in C
 See LICENSE

 Process the digest string.
 This computes checksums!
 ************************************************/
// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "seal.hpp"
#include "files.hpp"
#include "sign.hpp"

// For openssl 3.x
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>

/**************************************
 RangeErrorCheck(): Is the computed range valid?
 Sets error as needed.
 **************************************/
sealfield *	RangeErrorCheck	(sealfield *Rec, uint64_t sum[2], mmapfile *Mmap)
{
  // Idiot-check the range
  if (sum[0]==sum[1]) { return(Rec); } // sure, permit an empty range
  if (sum[0] > Mmap->memsize) // sum went negative
	{
	Rec = SealSetText(Rec,"@error","Invalid range; start of range is beyond end of file");
	}
  if (sum[1] > Mmap->memsize)
        {
	Rec = SealSetText(Rec,"@error","Invalid range; end of range is beyond end of file");
	}
  if (sum[0] >= sum[1])
        {
	Rec = SealSetText(Rec,"@error","Invalid range; start of range is after end of range");
	}
  return(Rec);
} /* RangeErrorCheck() */

/**************************************
 SealGetMdfFromString(): Given a digest algorithm name, get the EVP_MD function.
 Defaults to sha256 when not specified
 Returns NULL on unsupported algorithm.
 **************************************/
const EVP_MD* (*SealGetMdfFromString(const char *da))(void)
{
  if (!da || !strcmp(da,"sha256")) { return EVP_sha256; } // default
  if (!strcmp(da,"sha224")) { return EVP_sha224; }
  if (!strcmp(da,"sha384")) { return EVP_sha384; }
  if (!strcmp(da,"sha512")) { return EVP_sha512; }
  return NULL;
} /* SealGetMdfFromString() */

/**************************************
 SealDigest(): Given a file, compute the digest!
 This uses 'da', 'b', 's', and 'p' arguments.
 Computes the digest and stores binary data in @digest1.
 Stores the byte range in '@digestrange'.
 Sets '@sflags0' and '@sflags1' to store summaries of range
 Any error messages are stored in @error.
 NOTE: Permits two Mmap files for concatenation (e.g., sidecar);
 MmapPre is prefaced before an 'F' for computing the digest.
 **************************************/
sealfield *	SealDigest	(sealfield *Rec, mmapfile *Mmap, mmapfile *MmapPre)
{
  sealfield *digestbin;
  char *da; // digest algorithm
  char *b; // bytes to include in the digest
  size_t *s; // start and end of the current signature
  size_t *p; // start and end of the previous signature
  uint32_t seg[2]; // for tracking the segment (debugging)
  int state; // finite state machine

  // Should never happen
  if (!Rec || !Mmap) { return(Rec); }
  Rec = SealDel(Rec,"@error");
  Rec = SealDel(Rec,"@digestrange");
  Rec = SealDel(Rec,"@digest1");
  Rec = SealDel(Rec,"@digest2");
  Rec = SealDel(Rec,"@sflags0");
  Rec = SealDel(Rec,"@sflags1");

  // Load parameters
  s = SealGetIarray(Rec,"@s"); // should always be set
  p = SealGetIarray(Rec,"@p"); // should always be set

  /* Prepare the hasher! */
  const EVP_MD* (*mdf)(void);
  da = SealGetText(Rec,"da");
  mdf = SealGetMdfFromString(da);
  if (!mdf)
    {
    if (!da) { da = (char*)""; } // prevent crash
    Rec = SealSetText(Rec,"@error","Unknown digest algorithm (da=");
    Rec = SealAddText(Rec,"@error",da);
    Rec = SealAddText(Rec,"@error",")");
    return(Rec);
    }

  EVP_MD_CTX* ctx64 = EVP_MD_CTX_new();
  EVP_DigestInit(ctx64, mdf());

  /* Parse the byte string! */
  const char *ValidChar[]=
    {
    // first offset
    "+-pPsSfF0123456789~", // beginning or after ","
    "+-~", // finished reading offset (+- are for continuation)
    "pPsSfF0123456789", // after +/-
    // second offset (after "~")
    "+-pPsSfF0123456789,", // beginning or after "~"
    "+-,", // finished reading offset (+- are for continuation)
    "pPsSfF0123456789", // after +/-
    };
  int i,acc;
  uint64_t sum[2]; // total and accumulator
  int Addsym=1; // for addition (-1 for subtraction)
  state=acc=sum[0]=sum[1]=0;
  seg[0]=seg[1]=0;
  /*****
   State machine:
   0 = loading range start value (ends at "~")
   1 = loading range start value's additional offset info
   2 = loading range start value's additional offset value
   3 = loading range end value (ends at "~")
   4 = loading range end value's additional offset info
   5 = loading range end value's additional offset value
   *****/
  b = SealGetText(Rec,"b");
  for(i=0; b[i]; i++)
    {
    if (!strchr(ValidChar[state],b[i]))
	{
	// Invalid b= list
	Rec = SealSetText(Rec,"@error","Invalid range in b='");
	Rec = SealAddText(Rec,"@error",b);
	Rec = SealAddText(Rec,"@error","' in '");
	Rec = SealAddTextLen(Rec,"@error",(int)(i-seg[0]),b+seg[0]);
	Rec = SealAddText(Rec,"@error","'");
	goto Abort;
	}
    if (b[i]=='+') // addition symbol
      {
      if (state < 3) { sum[0] += acc*Addsym; state=2; }
      else { sum[1] += acc*Addsym; state=5; }
      Addsym=1; acc=0;
      }
    else if (b[i]=='-') // subtraction symbol
      {
      if (state < 3) { sum[0] += acc*Addsym; state=2; }
      else { sum[1] += acc*Addsym; state=5; }
      Addsym=-1; acc=0;
      }

    else if (b[i]=='S') // start of current signature
      {
      if (state < 3)
	{
	sum[0] += s[0]*Addsym; state=1;
	Rec = SealAddC(Rec,"@sflags0",'S');
	}
      else
	{
	sum[1] += s[0]*Addsym; state=4;
	Rec = SealAddC(Rec,"@sflags1",'S');
	}
      acc=0;
      }

    else if (b[i]=='s') // end of current signature
      {
      if (state < 3)
	{
	sum[0] += s[1]*Addsym; state=1;
	Rec = SealAddC(Rec,"@sflags0",'s');
	}
      else
	{
	sum[1] += s[1]*Addsym; state=4;
	Rec = SealAddC(Rec,"@sflags1",'s');
	}
      acc=0;
      }

    else if (b[i]=='P') // start of previous signature
      {
      if ((p[0] == 0) && MmapPre) // For a sidecar, add in the source media
	{
	EVP_DigestUpdate(ctx64,MmapPre->mem,MmapPre->memsize);
	}

      if (state < 3)
	{
	sum[0] += p[0]*Addsym; state=1;
	Rec = SealAddC(Rec,"@sflags0",'P');
	}
      else
	{
	sum[1] += p[0]*Addsym; state=4;
	Rec = SealAddC(Rec,"@sflags1",'P');
	}
      acc=0;
      }

    else if (b[i]=='p') // end of previous signature
      {
      if (state < 3)
	{
	sum[0] += p[1]*Addsym; state=1;
	Rec = SealAddC(Rec,"@sflags0",'p');
	}
      else
	{
	sum[1] += p[1]*Addsym; state=4;
	Rec = SealAddC(Rec,"@sflags1",'p');
	}
      acc=0;
      }

    else if (b[i]=='F') // start of file
      {
      if (MmapPre) // For a sidecar, add in the source media
	{
	EVP_DigestUpdate(ctx64,MmapPre->mem,MmapPre->memsize);
	}

      if (state < 3)
	{
	sum[0] += 0*Addsym; state=1;
	Rec = SealAddC(Rec,"@sflags0",'F');
	}
      else // end is relative to start?
	{
	sum[1] += 0*Addsym; state=4;
	Rec = SealAddC(Rec,"@sflags1",'F');
	}
      acc=0;
      }

    else if (b[i]=='f') // end of file
      {
      if (state < 3)
	{
	sum[0] += (Mmap->memsize)*Addsym; state=1;
	Rec = SealAddC(Rec,"@sflags0",'f');
	}
      else
	{
	sum[1] += (Mmap->memsize)*Addsym; state=4;
	Rec = SealAddC(Rec,"@sflags1",'f');
	}
      acc=0;
      }

    else if (isdigit(b[i])) // numeric offset
      {
      // add digit to accumulator
      acc = acc*10;
      acc += b[i]-'0';
      if (state < 3) { state=0; }
      else { state=3; }
      }
    else if (b[i]=='~') // switch from start of range to end of range
      {
      sum[0] += acc*Addsym;
      acc=0; Addsym=1;
      state=3;
      }
    else if (b[i]==',') // end of range!
      {
      seg[1] = i;

      // No value? assume end of file
      if ((state==3) && (acc==0))
	{
	sum[1]=Mmap->memsize;
	}
      else { sum[1] += acc*Addsym; }

      // Check the range
      // sum is size_t/unsigned. If it goes negative, it will be larger than memsize.
      if ((sum[1] < sum[0]) || (sum[0] > Mmap->memsize) || (sum[1] > Mmap->memsize))
	{
	Rec = SealSetText(Rec,"@error","Invalid range in b='");
	Rec = SealAddText(Rec,"@error",b);
	Rec = SealAddText(Rec,"@error","'");
	if (sum[0] > Mmap->memsize) { Rec = SealAddText(Rec,"@error","; underflow"); }
	if (sum[1] > Mmap->memsize) { Rec = SealAddText(Rec,"@error","; overflow"); }
	if (sum[1] < sum[0]) { Rec = SealAddText(Rec,"@error","; range begins after it ends"); }
	goto Abort;
	}

      //DEBUGPRINT("Segment: seg=%d '%.*s', range: %u-%u",state,(int)(seg[1]-seg[0]),b+seg[0],(uint)sum[0],(uint)sum[1]);
      Rec = RangeErrorCheck(Rec,sum,Mmap);
      if (SealSearch(Rec,"@error"))
	{
	goto Abort;
	}

      // If it made it to here, then it's a valid range!
      if (sum[1] > sum[0])
	{
	Rec = SealAddI(Rec,"@digestrange",sum[0]);
	Rec = SealAddI(Rec,"@digestrange",sum[1]);
	// Update digest
	EVP_DigestUpdate(ctx64,Mmap->mem+sum[0],sum[1]-sum[0]);
	//DEBUGPRINT("Segment: seg=%d '%.*s', range: %u-%u (0x%x - 0x%x)",state,(int)(seg[1]-seg[0]),b+seg[0],(uint)sum[0],(uint)sum[1],(uint)sum[0],(uint)sum[1]);
	}
      state=acc=sum[0]=sum[1]=0; Addsym=1;
      seg[0] = i+1;
      }
    } // for reading b string

  // No more string! Anything left to add?
  //DEBUGPRINT("State=%d  sum=%ld %ld  acc=%ld",state,(long)sum[0],(long)sum[1],(long)acc);
  if (state==3) { sum[1] += acc*Addsym; state=4; }

  seg[1] = i;
  if (state==0) { ; }
  else if (state==4)
    {
    Rec = RangeErrorCheck(Rec,sum,Mmap);
    if (SealSearch(Rec,"@error")) { goto Abort; }
    if (sum[1] > sum[0])
	{
	Rec = SealAddI(Rec,"@digestrange",sum[0]);
	Rec = SealAddI(Rec,"@digestrange",sum[1]);
	//DEBUGPRINT("Segment: seg=%d '%.*s', range: %u-%u (0x%x - 0x%x)",state,(int)(seg[1]-seg[0]),b+seg[0],(uint)sum[0],(uint)sum[1],(uint)sum[0],(uint)sum[1]);
	// Update digest
	EVP_DigestUpdate(ctx64,Mmap->mem+sum[0],sum[1]-sum[0]);
	}
    }
  else if (state == 5) // end of range
    {
    sum[1] += acc*Addsym;
    Rec = RangeErrorCheck(Rec,sum,Mmap);
    if (SealSearch(Rec,"@error")) { goto Abort; }
    }
  else // invalid end state
    {
    Rec = SealSetText(Rec,"@error","Invalid range in b='");
    Rec = SealAddText(Rec,"@error",b);
    Rec = SealAddText(Rec,"@error","' at end of string");
    goto Abort;
    }

  /* Finish the digest! */
  unsigned int mdsize;
  mdsize = EVP_MD_size(mdf()); // digest size
  Rec = SealAlloc(Rec,"@digest1",mdsize,'b'); // binary digest
  digestbin = SealSearch(Rec,"@digest1");
  EVP_DigestFinal(ctx64,digestbin->Value,&mdsize); // store the digest

#if 0
  if (Verbose > 0)
    {
    unsigned int i;
    printf(" Digest: ");
    for(i=0; i < mdsize; i++) { printf("%02x",digestbin->Value[i]); }
    printf("\n");
    }
#endif

Abort:
  EVP_MD_CTX_free(ctx64);
  return(Rec);
} /* SealDigest() */

/**************************************
 SealDoubleDigest(): If there's a date or id,
 then add them to the digest.
 This uses binary '@digest1', 'id', '@sigdate', and 'da' arguments.
 Computes the digest and places new data in @digest2.
 Any error messages are stored in @error.
 **************************************/
sealfield *	SealDoubleDigest	(sealfield *Rec)
{
  sealfield *digestbin;
  sealfield *SigDate=NULL;
  sealfield *UserId=NULL;
  const char *DigestAlg;
  unsigned int mdsize;
  unsigned char *mdval;
  EVP_MD_CTX *ctx64;
  const EVP_MD* (*mdf)(void);

  /*****
   If there is an id or a date, then add those to the digest.
   This is the double-digest step.
   It will be one of these:
        newdigest = hash(date:userid:newdigest)
        newdigest = hash(date:newdigest)
        newdigest = hash(userid:newdigest)
   *****/

  UserId = SealSearch(Rec,"id"); // could be empty
  if (UserId && !UserId->ValueLen) { UserId=NULL; }
  SigDate = SealSearch(Rec,"@sigdate"); // if it exists, should not be empty
  if (SigDate && !SigDate->ValueLen) { SigDate=NULL; }

  if (!UserId && !SigDate) { return(Rec); }

  Rec = SealCopy(Rec,"@digest2","@digest1");
  digestbin = SealSearch(Rec,"@digest2"); // could be empty
  if (!digestbin) // should never happen
    {
    if (!SealSearch(Rec,"@error")) { Rec = SealSetText(Rec,"@error","Digest not computed"); }
    return(Rec);
    }

  DigestAlg = SealGetText(Rec,"da"); // SEAL's 'da' parameter
  if (!DigestAlg) // should never happen, but just in case
    {
    Rec = SealSetText(Rec,"da","sha256"); // default
    DigestAlg = SealGetText(Rec,"da");
    }
  mdf = SealGetMdfFromString(DigestAlg);
  if (!mdf) // should never happen
    {
    Rec = SealSetText(Rec,"@error","Unsupported digest algorithm (da=");
    Rec = SealAddText(Rec,"@error",DigestAlg);
    Rec = SealAddText(Rec,"@error",")");
    return(Rec);
    }

  // It needs double digest!
  ctx64 = EVP_MD_CTX_new();
  EVP_DigestInit(ctx64, mdf());
  if (SigDate)
        {
        EVP_DigestUpdate(ctx64,SigDate->Value,SigDate->ValueLen);
        EVP_DigestUpdate(ctx64,":",1);
        }
  if (UserId)
        {
        EVP_DigestUpdate(ctx64,UserId->Value,UserId->ValueLen);
        EVP_DigestUpdate(ctx64,":",1);
	}

  EVP_DigestUpdate(ctx64,digestbin->Value,digestbin->ValueLen);

  mdsize = EVP_MD_size(mdf()); // digest size
  mdval = (unsigned char*)calloc(mdsize+4,1); // 4 bytes extra for safety
  EVP_DigestFinal(ctx64,mdval,&mdsize); // I have the digest!
  EVP_MD_CTX_free(ctx64);

  // Replace vf with the new digest
  digestbin->ValueLen = mdsize;
  free(digestbin->Value);
  digestbin->Value = (byte*)mdval;
#if 0
  if (Verbose > 0)
    {
    unsigned int i;
    printf(" Double Digest: ");
    for(i=0; i < mdsize; i++) { printf("%02x",digestbin->Value[i]); }
    printf("\n");
    }
#endif

  return(Rec);
} /* SealDoubleDigest() */
