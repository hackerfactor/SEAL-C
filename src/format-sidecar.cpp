/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling Sidecars.

 A sidecar is a special case: the signature(s) are outside of the file.
 This is intended for cases where the media is read-only, like legal evidence or a DVD.

 For validating (read-only):
   - Validate the sidecar
   - Then validate the source media (in case it has it's own signature).

 For signing (write-only):
   - If the sidecar doesn't exist, then create it.
   - Process the sidecar as a text file.
     EXCEPT: Use the source media as a prefaced data chunk for any signatures.
 ************************************************/
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "seal.hpp"
#include "seal-parse.hpp"
#include "sign.hpp"
#include "files.hpp"
#include "formats.hpp"

/**************************************
 Seal_Sidecar(): Process sidecar file
 Reads every seal signature in the sidecar.
 **************************************/
sealfield *	Seal_Sidecar	(sealfield *Args, mmapfile *MmapPre)
{
  const char *Srcname;
  char *sidecar;
  mmapfile *MmapSidecar=NULL;
  bool FreeMmapSidecar=false; // set when I allocated my own MmapSidecar for a zero-length file

  sidecar = SealGetText(Args,"sidecar");
  if (!sidecar) // no sidecar!
    {
    printf(" No SEAL sidecar found.\n");
    return(Args);
    }
  // The 'sidecar' name is a template pattern. Convert it to a real name
  Srcname = SealGetText(Args,"@SourceMedia");
  sidecar = MakeFilename(sidecar,Srcname);

  if (SealIsReadable(sidecar,true))
    {
    MmapSidecar=MmapFile(sidecar,PROT_ABORT);
    }
  else if (SealGetText(Args,"@FilenameOut")) // this was set when writing
    {
    FILE *fp;
    fp = fopen(sidecar,"ab"); // create as needed
    if (fp) // if zero-length file
      {
      fseek(fp,0,SEEK_END); // jump to end of file
      if (ftell(fp) <= 0)
	{
	MmapSidecar = (mmapfile*)calloc(sizeof(mmapfile),1);
	FreeMmapSidecar = true;
	}
      fclose(fp);
      }
    // else fp==NULL: What if it didn't get created? MmapFile will fail.
    }
  // else MmapSidecar is null

  if (MmapPre)
    {
    Args = Seal_Text(Args,MmapSidecar,MmapPre); // Add a signature as needed
    }
  else // no source file
    {
    sealfield *rec; // SEAL record
    mmapfile *MmapOut;
    size_t InsertOffset=0;
    char *Opt;

    // Scan text for any/all SEAL records
    InsertOffset = MmapSidecar->memsize;
    Args = SealVerifyBlock(Args, 0, InsertOffset, MmapSidecar, NULL);
    // Sign as needed
    Opt = SealGetText(Args,"options"); // grab options list

    Args = SealDel(Args,"b");
    if (strchr(SealGetText(Args,"@sflags"),'F')) // if exists, then append
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
    Args = SealAddText(Args,"b","~S");

    // Check for appending
    if (!Opt || !strstr(Opt,"append")) // if not append
        {
        Args = SealAddText(Args,"b",",s~f");
        }
    else // if appending
        {
        Args = SealAddText(Args,"b",",s~s+3"); // +3 for '"/>' or '"?>'
        }

    // Get the record
    Args = SealRecord(Args); // get placeholder

    // Create the block
    Args = SealSetText(Args,"@BLOCK",InsertOffset ? "\n" : "");

    // Make '@s' relative to block
    rec = SealSearch(Args,"@BLOCK");
    SealIncIindex(Args, "@s", 0, rec->ValueLen);
    SealIncIindex(Args, "@s", 1, rec->ValueLen);

    // Add record
    rec = SealSearch(Args,"@record");
    Args = SealAddBin(Args,"@BLOCK",rec->ValueLen,rec->Value);
    Args = SealAddText(Args,"@BLOCK","\n");

    MmapOut = SealInsert(Args,MmapSidecar,InsertOffset);
    if (MmapOut)
      {
      // Sign it!
      SealSign(Args,MmapOut,NULL);
      MmapFree(MmapOut);
      }
    } // if no source file; just sidecar

  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf(" No SEAL signatures found.\n");
    }
  // Seal_Text() tests for "No SEAL signatures found.".

  free(sidecar);
  if (!MmapSidecar) { ; } // No cleanup
  else if (FreeMmapSidecar) { free(MmapSidecar); }
  else { MmapFree(MmapSidecar); }
  return(Args);
} /* Seal_Sidecar() */

