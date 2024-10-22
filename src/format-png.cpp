/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling PNG files.

 PNG files are one of the nicest formats for parsing.
 It has an 8-byte magic header that identifies the file format:
    "137 P N G \r \n 26 \n"

 Then comes a series of chunks.
 Each 'chunk' consists of:

   4 bytes : length of the chunk
     No chunk can be longer than this size.

   4 bytes : Four character code (FCC) defining the type of chunk.
     1st letter: uppercase is mandatory, lowercase is ancillary (optional)
     2nd letter: uppercase is public data, lowercase is private (unpublished)
     3rd letter: reserved, always uppercase.
     4th letter: "safe to copy", uppercase is unsafe, lowercase is safe.
     For encoding, this implementation uses: sEAl
       - While not in the published list of known PNG chunks,
         the specs are public so the 2nd letter is capitalized.
       - While copying the chunk will result in an invalid signature,
         we mark it as safe-to-copy because we want to detect the alteration.
     However, for decoding, it will accept any: sEAl, sEAL, SeAl, etc.

   length bytes : the data for the chunk

   4 bytes : CRC checksum to detect chunk tampering.

 The final chunk is IDAT, which should have zero bytes of data:
    \0\0\0\0 IDAT \xAE\x42\x60\x82
 (The CRC for zero bytes is always the same.)

 The sEAl chunk can appear anywhere before IEND.
 However, ExifTool will complain if it appears after the first IDAT.
 Solution?
   For regular PNGs, store it right after IHDR.
   For APNG (animated), store it after each IDAT/fDAT sequence.

 For PNG encoding, only one sEAl chunk can be valid.
   - Check if there is any existing seal chunks.
   - Prompt the user if they are sure they want to replace it.
   - Never have multiple seal chunks.
   - The seal range must skip the CRC since that is computed after
     storing the seal record: b='F~S,s~s+4,s+8~f'

 For APNG encoding, permit appending.
   - Appending uses b='p~S,s~s+4'
   - Finalizing inserts before the IEND: b='p~S,s~s+4,s+8~f'
   - If there was tampering, then it is perfectly acceptable to
     have one invalid seal chunk followed by a valid chunk.
     It means one b=range is invalid, but the next one is still valid.
 ************************************************/
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "seal.hpp"
#include "seal-parse.hpp"
#include "sign-digest.hpp"
#include "sign-local.hpp"
#include "sign-remote.hpp"
#include "sign-record.hpp"
#include "sign-verify.hpp"
#include "files.hpp"
#include "formats.hpp"

#pragma GCC visibility push(hidden)
static uint32_t _PNG_table[256] = {255};

/**************************************
 _PNGCrc32(): Calculate the PNG checksum.
 PNG CRC covers type+data, not chunk length or checksum.
 **************************************/
uint32_t	_PNGCrc32	(uint32_t DataLen, byte *Data)
{
  uint32_t crc;
  size_t n,j;

  // Populate the CRC table
  if (_PNG_table[0]==255)
    {
    memset(_PNG_table,0,256*sizeof(uint32_t));
    for(n=0; n < 256; n++)
      {
      crc = n;
      for(j=0; j < 8; j++)
	{
	if (crc & 1) { crc = 0xedb88320L ^ (crc>>1); }
	else { crc = (crc>>1); }
	}
      _PNG_table[n] = crc;
      }
    }

  /*****
   Calculate the current value.
   NOTE: This uses a do-loop.
   Why? Because we don't want an infinite loop if DataLen=max size.
   *****/
  crc = 0xffffffffL; // initial value
  for(n=0; n < DataLen; n++)
    {
    crc = _PNG_table[(crc^Data[n]) & 0xff]^(crc>>8);
    }
  crc = crc ^ 0xffffffffL;
  return(crc);
} /* _PNGCrc32() */

/**************************************
 _PNGchunkSign(): Generate the signature chunk.
 If Mmap is set, then compute checksum and set @p and @s.
 Otherwise, return a stub chunk.
 Returns record in [@record]
 Returns chunk in [@PNGchunk]
 Returns offset and length to the signature in [@s]
 **************************************/
sealfield *	_PNGchunkSign	(sealfield *Args, mmapfile *Mmap, size_t Offset)
{
  const char *ChunkName="seAl";
  char *Opt;
  uint32_t u32,opti;
  size_t ChunkHeaderSize=0;
  sealfield *rec, *sig;

  ChunkHeaderSize=8; // By default: there is an 8-byte chunk header

  /*****
   Load options (if present)
   Determine the type of chunk for writing.

   For signing:
   If the options includes append, then append to the file.
   If the options includes any valid PNG capitalization of
   "seAl" or "teXt", then use that chunk name for writing.
   *****/
  Opt = SealGetText(Args,"options"); // grab options list
  // Determine the new chunk name
  if (Opt)
    {
    u32 = strlen(Opt);
    // User can specify alternate capitalization.
    // Currently only supports variations of seal and text.
    // TBD: consider adding custom format support for exif and xmp
    for(opti=0; opti+4 <= u32; opti++)
      {
      if (!isupper(Opt[opti+2])) { continue; } // invalid PNG format
      if (!strncasecmp(Opt+opti,"seal",4)) { ChunkName=Opt+opti; ChunkHeaderSize=8; break; }
      if (!strncasecmp(Opt+opti,"text",4)) { ChunkName=Opt+opti; ChunkHeaderSize=8+5; break; }
      }
    }

  /*****
   Determine the byte range for the digest.
   The first record should start from the start of the file.
   The last record goes to the end of the file. Unless...
   Unless it is appending.
   *****/
  Args = SealDel(Args,"b");
  if (SealGetCindex(Args,"@sflags",0)=='F') // if exists, then append
	{
	// if appending, overlap signatures to prevent insertion attacks.
	Args = SealSetText(Args,"b","P");
	}
  else
	{
	// if starting from the beginning of the file
	Args = SealSetText(Args,"b","F");
	}
  // Range covers signature and end of record.
  Args = SealAddText(Args,"b","~S,s~s+3"); // 3 for '"/>'

  // Check for appending
  if (!Opt || !strstr(Opt,"append")) // if not append
	{
	// Skip the PNG checksum and finalize to the end of file ("f")
	Args = SealAddText(Args,"b",",s+7~f");
	}
  // else: if appending, do nothing and leave it open.

  /*****
   create the SEAL record!
   NOTE: 
   *****/
  Args = SealRecord(Args); // populate with placeholder at "@S" (capital-S)
  rec = SealSearch(Args,"@record");
  if (rec==NULL) // should never happen
    {
    printf("ERROR: Cannot generate the signature. Aborting.\n");
    exit(1);
    }

  // Compute the signature
  if (Mmap)
    {
    /*****
     The digest uses P~p and S~s (stored in @p and @s).
     However, I only have the SEAL record.
     "@S" is the signature location, relative to the start of the SEAL record.

     Make 'S~s' relative to the start of the file.
     The SEAL record is being built inside a PNG chunk.
     The PNG chunk starts at Offset (absolute file location).
     The PNG chunk has an 8 byte header (length+type).
     A text chunk has a 5 byte field (+5).
     So the start of the signature, relative to the file, is: @S + Offset + ChunkHeader
     *****/
    Args = SealCopy(Args,"@sflags","@sflags"); // Flags may be updated
    Args = SealCopy(Args,"@p","@s"); // Rotates previous @s to @p
    Args = SealSetIindex(Args,"@s",0, SealGetIindex(Args,"@S",0)+Offset+ChunkHeaderSize);
    Args = SealSetIindex(Args,"@s",1, SealGetIindex(Args,"@S",1)+Offset+ChunkHeaderSize);

    /* Compute the digest and sign it */
    Args = SealDigest(Args, Mmap); // compute digest
    switch(SealGetCindex(Args,"@mode",0)) // sign it
      {
      case 'S': Args = SealSignURL(Args); break;
      case 's': Args = SealSignLocal(Args); break;
      default: break; // never happens
      }

    // Signature is ready-to-go in '@signatureenc'
    // Size is already pre-computed, so it will fit for overwriting.
    // Copy signature into record.
    sig = SealSearch(Args,"@signatureenc");
    memcpy(rec->Value+SealGetIindex(Args,"@S",0), sig->Value, sig->ValueLen);
    }

  /*****
   Convert the signature in '@record' to a PNG chunk.
   *****/
  Args = SealDel(Args,"@PNGchunk");

  // Placeholder for length
  Args = SealAddTextPad(Args,"@PNGchunk",4," ");

  // Insert: Chunk name
  Args = SealAddTextLen(Args,"@PNGchunk",4,ChunkName);

  // Insert: chunk-specific data
  if (!strncasecmp(ChunkName,"text",4))
    {
    // PNG text begins with a keyword and null
    Args = SealAddBin(Args,"@PNGchunk",5,(const byte*)"seal\0");
    }

  // Insert: SEAL record
  Args = SealAddBin(Args,"@PNGchunk",rec->ValueLen, rec->Value);

  // Compute and insert the size
  rec = SealSearch(Args,"@PNGchunk");
  u32 = rec->ValueLen - 8;
  Args = SealSetCindex(Args,"@PNGchunk",0,(u32 >> 24)&0xff);
  Args = SealSetCindex(Args,"@PNGchunk",1,(u32 >> 16)&0xff);
  Args = SealSetCindex(Args,"@PNGchunk",2,(u32 >> 8)&0xff);
  Args = SealSetCindex(Args,"@PNGchunk",3,u32 & 0xff);

  // Compute and insert CRC (big endian)
  rec = SealSearch(Args,"@PNGchunk");
  u32 = _PNGCrc32(rec->ValueLen-4, rec->Value+4); // CRC covers type+data
  Args = SealAddC(Args,"@PNGchunk",(u32 >> 24)&0xff);
  Args = SealAddC(Args,"@PNGchunk",(u32 >> 16)&0xff);
  Args = SealAddC(Args,"@PNGchunk",(u32 >> 8)&0xff);
  Args = SealAddC(Args,"@PNGchunk",u32 & 0xff);

  rec->Type = 'x'; // debug with hex dump

  return(Args);
} /* _PNGchunkSign() */

#pragma GCC visibility pop

/**************************************
 Seal_isPNG(): Is this file a PNG?
 Returns: true or false.
 **************************************/
bool	Seal_isPNG	(mmapfile *Mmap)
{
  if (!Mmap || (Mmap->memsize < 20)) { return(false); }

  if ( /* header begins with "137 P N G \r \n 26 \n" */
        memcmp(Mmap->mem,"\x89PNG\r\n\x1a\n",8)
     )
        {
        return(false);   /* not a PNG! */
        }
  return(true);
} /* Seal_isPNG() */

/**************************************
 Seal_PNGsign(): Sign a PNG.
 Insert a PNG signature.
 **************************************/
sealfield *	Seal_PNGsign	(sealfield *Rec, mmapfile *Mmap, size_t IEND_offset)
{
  const char *fname;
  FILE *Fout;
  sealfield *chunk;
  mmapfile *Mnew;
  size_t OldChunkLen;

  fname = SealGetText(Rec,"@FilenameOut");
  if (!fname) { return(Rec); } // not signing

  // Check if file is finalized (abort if it is)
  if (SealGetCindex(Rec,"@sflags",1)=='f')
	{
	fprintf(stderr,"ERROR: PNG is finalized; cannot sign. Aborting.\n");
	exit(1);
	}

  /*****
   The easy way:
   Rewrite the file with a stubbed signature and PNG CRC.
   Compute the new checksum and CRC.
   Then update the new file.
   *****/
  Fout = SealFileOpen(fname,"w+b"); // returns handle or aborts

  // Grab the new chunk placeholder
  Rec = _PNGchunkSign(Rec,NULL,IEND_offset);
  chunk = SealSearch(Rec,"@PNGchunk");

  // Write to file!!!
  rewind(Fout); // should not be needed

  // Store up to the IEND
  SealFileWrite(Fout, IEND_offset, Mmap->mem);
  // Append signature chunk
  SealFileWrite(Fout, chunk->ValueLen, chunk->Value);
  // Store everything else (IEND and any trailers)
  SealFileWrite(Fout, Mmap->memsize - IEND_offset, Mmap->mem + IEND_offset);
  SealFileClose(Fout);

  // Compute new digest
  Mnew = MmapFile(fname,PROT_WRITE);
  Rec = _PNGchunkSign(Rec,Mnew,IEND_offset);
  OldChunkLen = chunk->ValueLen;
  chunk = SealSearch(Rec,"@PNGchunk");
  chunk->Type = 'x';

  // Chunk size better not change!!!
  if (OldChunkLen != chunk->ValueLen)
	{
	fprintf(stderr,"ERROR: record size changed while writing. Aborting.\n");
	exit(1);
	}

  // Update file with new signature
  memcpy(Mnew->mem + IEND_offset, chunk->Value, chunk->ValueLen);
  MmapFree(Mnew);

  Rec = SealRotateRecords(Rec);
  printf("Signature record #%ld added.\n",(long)SealGetIindex(Rec,"@s",2));
  return(Rec);
} /* Seal_PNGsign() */

/**************************************
 Seal_PNG(): Process a PNG.
 Reads every seal signature.
 **************************************/
sealfield *	Seal_PNG	(sealfield *Args, mmapfile *Mmap)
{
  sealfield *Rec;
  size_t Offset;
  size_t RecEnd=0;
  size_t IEND_offset=0;
  uint32_t ChunkOffset,ChunkSize;
  const char *FourCC;

  // Make sure it's a PNG.
  if (!Seal_isPNG(Mmap)) { return(Args); }

  /*****
   Walk through each PNG chunk.
   If it's a seal, text, or itxt, check for signature.
   If it's an exif, check for special exif processing.
   And track the location of the IEND.

   Ignore all other chunks.
   Especially zTxt! Signatures cannot be compressed.

   - Do not verify chunk checksums. (I'm fine if they are wrong.)
   - Abort if the file appears corrupted. Do not sign corrupted files.
   - Ignore any data after the end of the IEND.

   =====
   Every chunk has 4-byte size + 4-byte FourCC + 4-byte checksum.
   But, it can be longer.

   =====
   When iterating, use Rec instead of Args.
   This way, the scope of all values is limited to Rec.
   When this finishes, moves the values I want to keep back into Args.
   *****/
  Offset=8; // skip PNG header
  while(Offset+12 <= Mmap->memsize)
    {
    // Size is always big-endian
    ChunkSize = (Mmap->mem[Offset+0] << 24) |
		(Mmap->mem[Offset+1] << 16) |
		(Mmap->mem[Offset+2] << 8) |
		(Mmap->mem[Offset+3]);
    FourCC = (const char*)Mmap->mem + Offset + 4;
    if ((ChunkSize > Mmap->memsize) ||
	(Offset+12+ChunkSize > Mmap->memsize))
	{
	fprintf(stderr,"ERROR: PNG is corrupted. Aborting.\n");
	}

    //printf("PNG FourCC[%.4s]\n",FourCC); // DEBUGGING

    // Stop at the IEND
    if (!memcmp(FourCC,"IEND",4)) { IEND_offset = Offset; break; }
    // text or seal can encode a signature
    else if (!strncasecmp(FourCC,"text",4) ||
	     !strncasecmp(FourCC,"itxt",4) ||
	     !strncasecmp(FourCC,"seal",4))
	{
	// Process possible SEAL record.
	Rec=NULL;
	ChunkOffset=0;
	while(ChunkOffset < ChunkSize)
	  {
	  Rec = SealParse(ChunkSize-ChunkOffset,Mmap->mem+Offset+8+ChunkOffset,Offset+8+ChunkOffset,Args);
	  if (!Rec) { break; } // no record found; stop looking in this chunk

	  // Found a signature!
	  // Verify the data!
	  Rec = SealCopy2(Rec,"@pubkeyfile",Args,"@pubkeyfile");
	  Rec = SealVerify(Rec,Mmap);

	  // Iterate on remainder
	  RecEnd = SealGetIindex(Rec,"@RecEnd",0);
	  if (RecEnd <= 0) { RecEnd=1; } // should never happen, but if it does, stop infinite loops
	  ChunkOffset += RecEnd;

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
	}
    else if (!strncasecmp(FourCC,"exif",4))
	{
	// Process possible EXIF for SEAL record.
	// TBD
	}

    // On to the next chunk!
    Offset += ChunkSize + 12;
    }

  Args = Seal_PNGsign(Args,Mmap,IEND_offset); // Add a signature as needed
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf("No SEAL signatures found.\n");
    }

  return(Args);
} /* Seal_PNG() */

