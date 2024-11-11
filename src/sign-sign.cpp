/************************************************
 SEAL: Code to handle general signing.
 See LICENSE
 ************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "seal.hpp"
#include "files.hpp"
#include "sign.hpp"

/**************************************
 SealInsert(): Add a signature block into the file.
   MmapIn is source file to copy/insert.
   '@FilenameOut' contains destination filename.
   '@BLOCK' contains ready-to-go block containing SEAL record.
   '@s' is relative to '@BLOCK'.
   InsertOffset = where to insert.
 Returns:  NULL on error, or:
   Updates '@s' to be relative to the file.
   Signature inserted.
   Mmap opened for writing! Caller must call MmapFree()!
 **************************************/
mmapfile *	SealInsert	(sealfield *Rec, mmapfile *MmapIn, size_t InsertOffset)
{
  const char *fname;
  FILE *Fout;
  sealfield *block;
  mmapfile *MmapOut;
  size_t *v;

  fname = SealGetText(Rec,"@FilenameOut");
  if (!fname || !fname[0]) { return(NULL); } // not signing

  // Grab the new block placeholder
  block = SealSearch(Rec,"@BLOCK");
  if (!block) { return(NULL); } // missing block! (called wrong)

  // Check if file is finalized (abort if it is)
  if (SealGetCindex(Rec,"@sflags",1)=='f')
	{
	fprintf(stderr," ERROR: File is finalized; cannot sign. Skipping.\n");
	return(NULL);
	}

  // Open file for writing!
  Fout = SealFileOpen(fname,"w+b"); // returns handle or aborts
  if (!Fout)
	{
	fprintf(stderr," ERROR: Cannot create file (%s). Aborting.\n",fname);
	exit(0x80);
	}
  rewind(Fout); // should not be needed

  // Copy up to the block
  if (InsertOffset > MmapIn->memsize) // padding?
    {
    size_t i;
    SealFileWrite(Fout, MmapIn->memsize, MmapIn->mem);
    for(i=MmapIn->memsize; i < InsertOffset; i++) { fputc('\0',Fout); }
    }
  else
    {
    SealFileWrite(Fout, InsertOffset, MmapIn->mem);
    }

  // Append signature block and update offsets
  SealFileWrite(Fout, block->ValueLen, block->Value);
  v = SealGetIarray(Rec,"@s");
  v[0] += InsertOffset;
  v[1] += InsertOffset;

  // Store everything else
  if (InsertOffset < MmapIn->memsize)
    {
    SealFileWrite(Fout, MmapIn->memsize - InsertOffset, MmapIn->mem + InsertOffset);
    }

  SealFileClose(Fout);

  // Prepare mmap
  MmapOut = MmapFile(fname,PROT_WRITE);
  return(MmapOut);
} /* SealInsert() */

/**************************************
 SealSign(): Sign a file.
 Insert a signature!
 Assumes:
   MmapOut is writable memory! from MmapFile(fname,PROT_WRITE).
   '@s' contains start and end of signature relative to file.
   Rec contains everything needed to compute the digest and signature:
     'da', 'b', 's', and 'p' arguments.
 Returns: true on success, false on failure (with error to stderr)
 **************************************/
bool	SealSign	(sealfield *Rec, mmapfile *MmapOut)
{
  const char *fname;
  sealfield *sig, *sigparm;
  size_t *s, *p;

  if (!MmapOut) { return(false); } // not signing
  fname = SealGetText(Rec,"@FilenameOut");
  if (!fname || !fname[0]) { return(NULL); } // not signing

  // Check if file is finalized (abort if it is)
  if (SealGetCindex(Rec,"@sflags",1)=='f')
	{
	fprintf(stderr," ERROR: File is finalized; cannot sign. Aborting.\n");
	exit(0x80);
	}

  // Compute new digest
  sigparm = SealClone(Rec);
  sigparm = SealDigest(sigparm,MmapOut);

  // Sign it (this creates '@signatureenc')
  switch(SealGetCindex(sigparm,"@mode",0)) // sign it
    {
    case 'M': case 'S': sigparm = SealSignURL(sigparm); break;
    case 'm': case 's': sigparm = SealSignLocal(sigparm); break;
    default: break; // never happens
    }

  // Signature is ready-to-go in '@signatureenc'
  // Size is already pre-computed, so it will fit for overwriting.
  // Copy signature into record.
  sig = SealSearch(sigparm,"@signatureenc");

  // Idiot checking: signature size must not change!
  s = SealGetIarray(Rec,"@s");
  p = SealGetIarray(Rec,"@p");
  if (!sig || (sig->ValueLen + s[0] != s[1]))
	{
	fprintf(stderr," ERROR: signature size changed while writing. Aborting.\n");
	exit(0x80);
	}

  // Update file with new signature
  memcpy(MmapOut->mem + s[0], sig->Value, sig->ValueLen);
  p[0] = s[0]; // rotate positions
  p[1] = s[1];
  p[2] = s[2];
  Rec = SealIncIindex(Rec,"@s",2,1); // increase number of signatures

  printf(" Signature record #%ld added: %s\n",(long)SealGetIindex(Rec,"@s",2),fname);
  if (Verbose) // if showing digest
    {
    sealfield *d;
    uint i;
    d = SealSearch(sigparm,"@digest1");
    if (d) // should always exist!
	{
	printf("  Digest: ");
	for(i=0; i < d->ValueLen; i++) { printf("%02x",d->Value[i]); }
	printf("\n");
	}
    d = SealSearch(sigparm,"@digest2");
    if (d) // may exist!
	{
	printf("  Double Digest: ");
	for(i=0; i < d->ValueLen; i++) { printf("%02x",d->Value[i]); }
	printf("\n");
	}
    }

  SealFree(sigparm);
  return(true);
} /* SealSign() */

