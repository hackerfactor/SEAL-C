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

  if (!MmapPre) // no source media!
    {
    printf(" No source media available.\n");
    return(Args);
    }

  sidecar = SealGetText(Args,"sidecar");
  if (!sidecar) // no sidecar!
    {
    printf(" No SEAL sidecar found.\n");
    return(Args);
    }
  // The 'sidecar' name is a template pattern. Convert it to a real name
  Srcname = SealGetText(Args,"@SourceMedia");
  sidecar = MakeFilename(sidecar,Srcname);

  if (SealGetText(Args,"@FilenameOut")) // this was set when writing
    {
    FILE *fp;
    fp = fopen(sidecar,"ab"); // create as needed
    if (fp) // if zero-length file
      {
      if (ftell(fp) <= 0)
	{
	MmapSidecar = (mmapfile*)calloc(sizeof(mmapfile),1);
	FreeMmapSidecar = true;
	}
      }
    if (fp) { fclose(fp); }
    // else fp==NULL: What if it didn't get created? MmapFile will fail.
    }
  else
    {
    MmapSidecar=MmapFile(sidecar,PROT_READ);
    }

  Args = Seal_Text(Args,MmapSidecar,MmapPre); // Add a signature as needed
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf(" No SEAL signatures found.\n");
    }

  free(sidecar);
  if (FreeMmapSidecar) { free(MmapSidecar); }
  else { MmapFree(MmapSidecar); }
  return(Args);
} /* Seal_Sidecar() */

