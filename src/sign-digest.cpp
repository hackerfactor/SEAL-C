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
 SealDigest(): Given a file, compute the digest!
 This uses 'da', 'b', 's', and 'p' arguments.
 Computes the digest and stores binary data in @digest.
 Stores the byte range in '@digestrange'.
 Any error messages are stored in @error.
 **************************************/
sealfield *	SealDigest	(sealfield *Rec, mmapfile *Mmap)
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

  // Load parameters
  s = SealGetIarray(Rec,"@s"); // should always be set
  p = SealGetIarray(Rec,"@p"); // should always be set

  /* Prepare the hasher! */
  const EVP_MD* (*mdf)(void);
  da = SealGetText(Rec,"da");
  if (!da || !strcmp(da,"sha256")) { mdf = EVP_sha256; } // default
  else if (!da || !strcmp(da,"sha224")) { mdf = EVP_sha224; }
  else if (!strcmp(da,"sha384")) { mdf = EVP_sha384; }
  else if (!strcmp(da,"sha512")) { mdf = EVP_sha512; }
  else
    {
    //fprintf(stderr,"ERROR: Unknown digest algorithm (da=%s).\n",da);
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
DEBUGWHERE();
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
      if (state < 3) { sum[0] += s[0]*Addsym; state=1; }
      else { sum[1] += s[0]*Addsym; state=4; }
      acc=0;
      }
    else if (b[i]=='s') // end of current signature
      {
      if (state < 3) { sum[0] += s[1]*Addsym; state=1; }
      else { sum[1] += s[1]*Addsym; state=4; }
      acc=0;
      }
    else if (b[i]=='P') // start of previous signature
      {
      if (state < 3) { sum[0] += p[0]*Addsym; state=1; }
      else { sum[1] += p[0]*Addsym; state=4; }
      Rec = SealSetCindex(Rec,"@sflags",2,'P'); // sig covers previous signature
      acc=0;
      }
    else if (b[i]=='p') // end of previous signature
      {
      if (state < 3) { sum[0] += p[1]*Addsym; state=1; }
      else { sum[1] += p[1]*Addsym; state=4; }
      acc=0;
      }
    else if (b[i]=='F') // start of file
      {
      if (state < 3) { sum[0] += 0*Addsym; state=1; }
      else { sum[1] += 0*Addsym; state=4; }
      Rec = SealSetCindex(Rec,"@sflags",0,'F'); // sig covers start
      acc=0;
      }
    else if (b[i]=='f') // end of file
      {
      if (state < 3) { sum[0] += Mmap->memsize*Addsym; state=1; }
      else { sum[1] += Mmap->memsize*Addsym; state=4; }
      Rec = SealSetCindex(Rec,"@sflags",1,'f'); // sig covers end
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
      if ((state==3) && (acc==0)) { sum[1]=Mmap->memsize; }
      else { sum[1] += acc*Addsym; }

      // Check the range
      if ((sum[1] < sum[0]) || (sum[1] > Mmap->memsize))
	{
	Rec = SealSetText(Rec,"@error","Invalid range in b='");
	Rec = SealAddText(Rec,"@error",b);
	Rec = SealAddText(Rec,"@error","'");
	if (sum[1] > Mmap->memsize) { Rec = SealAddText(Rec,"@error","; overflow"); }
	if (sum[1] < sum[0]) { Rec = SealAddText(Rec,"@error","; range begins after it ends"); }
DEBUGPRINT("Error: sum: %ld %ld vs %ld",(long)(sum[0]), (long)(sum[1]), (long)(Mmap->memsize));
DEBUGPRINT("Error: %s",SealGetText(Rec,"@error"));
	goto Abort;
	}

      //DEBUGPRINT("Segment: seg=%d '%.*s', range: %u-%u",state,(int)(seg[1]-seg[0]),b+seg[0],(uint)sum[0],(uint)sum[1]);
      Rec = RangeErrorCheck(Rec,sum,Mmap);
      if (SealSearch(Rec,"@error"))
	{
DEBUGWHERE();
	goto Abort;
	}

      // If it made it to here, then it's a valid range!
      if (sum[1] > sum[0])
	{
	Rec = SealAddI(Rec,"@digestrange",sum[0]);
	Rec = SealAddI(Rec,"@digestrange",sum[1]);
	EVP_DigestUpdate(ctx64,Mmap->mem+sum[0],sum[1]-sum[0]);
	//DEBUGPRINT("Segment: seg=%d '%.*s', range: %u-%u (0x%x - 0x%x)",state,(int)(seg[1]-seg[0]),b+seg[0],(uint)sum[0],(uint)sum[1],(uint)sum[0],(uint)sum[1]);
	}
      state=acc=sum[0]=sum[1]=0; Addsym=1;
      seg[0] = i+1;
      }
    } // for reading b string

  // No more string! Anything left to add?
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
	EVP_DigestUpdate(ctx64,Mmap->mem+sum[0],sum[1]-sum[0]);
	//DEBUGPRINT("Segment: seg=%d '%.*s', range: %u-%u (0x%x - 0x%x)",state,(int)(seg[1]-seg[0]),b+seg[0],(uint)sum[0],(uint)sum[1],(uint)sum[0],(uint)sum[1]);
	}
    }
  else if (state == 3) // start of next range and then ends
    {
    sum[1] = Mmap->memsize;
    Rec = RangeErrorCheck(Rec,sum,Mmap);
    if (SealSearch(Rec,"@error")) { goto Abort; }
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
  Rec = SealAlloc(Rec,"@digest",mdsize,'b'); // binary digest
  digestbin = SealSearch(Rec,"@digest");
  EVP_DigestFinal(ctx64,digestbin->Value,&mdsize); // store the digest

  if (Verbose > 1)
    {
    unsigned int i;
    printf("DEBUG Digest: ");
    for(i=0; i < mdsize; i++) { printf("%02x",digestbin->Value[i]); }
    printf("\n");
    }

Abort:
  EVP_MD_CTX_free(ctx64);
  return(Rec);
} /* SealDigest() */

/**************************************
 SealDoubleDigest(): If there's a date or id,
 then add them to the digest.
 This uses binary '@digest', 'id', '@sigdate', and 'da' arguments.
 Computes the digest and replaces binary data in @digest.
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

  digestbin = SealSearch(Rec,"@digest"); // could be empty
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
  if (!strcmp(DigestAlg,"sha224")) { mdf = EVP_sha224; }
  else if (!strcmp(DigestAlg,"sha256")) { mdf = EVP_sha256; }
  else if (!strcmp(DigestAlg,"sha384")) { mdf = EVP_sha384; }
  else if (!strcmp(DigestAlg,"sha512")) { mdf = EVP_sha512; }
  else // should never happen
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
  if (Verbose > 1)
    {
    unsigned int i;
    printf("DEBUG Double Digest: ");
    for(i=0; i < mdsize; i++) { printf("%02x",digestbin->Value[i]); }
    printf("\n");
    }

  return(Rec);
} /* SealDoubleDigest() */

