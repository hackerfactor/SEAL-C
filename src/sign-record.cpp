/************************************************
 SEAL: implemented in C
 See LICENSE

 Generate a SEAL record!
 A SEAL record is in the format: <seal ... />
 This code does NOT verify signtures or generate digests.
 It just populates the SEAL record.
 ************************************************/
// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "seal.hpp"
#include "seal-parse.hpp"

/********************************************************
 SealRecord(): Generate the record!
 Returns: '@record' with the complete record
 NOTE: The signature is likely wrong and stubbed out.
 Use @S and @s to identify where the signature is located
 relative to the record.
 ********************************************************/
sealfield *	SealRecord	(sealfield *Args)
{
  /*****
   If there's a digest, then include the signature.
   If there is no digest, then include padding.

   All strings should be encoded!
   *****/
  const char *Fields[] = {
    "seal",
    "kv",
    "ka",
    "da",
    "sf",
    "comment",
    "copyright",
    "info",
    "src",
    "srca",
    "srcd",
    // Never include srcf! That's always a local file.
    "id",
    "b",
    NULL
    };
  int f;
  sealfield *vf;

  // Start record
  Args = SealSetText(Args,"@record","<seal");

  // Add every field (if it exists
  for(f=0; Fields[f]; f++)
    {
    vf = SealSearch(Args,Fields[f]);
    if (!vf || !vf->ValueLen) { continue; }
    Args = SealCopy(Args,"@copy",Fields[f]);
    vf = SealSearch(Args,"@copy");
    SealStrEncode(vf);
    Args = SealAddText(Args,"@record"," ");
    Args = SealAddText(Args,"@record",Fields[f]);
    Args = SealAddText(Args,"@record","=\"");
    Args = SealAddText(Args,"@record",(char*)vf->Value);
    Args = SealAddText(Args,"@record","\"");
    }

  // Add the domain
  Args = SealAddText(Args,"@record"," d=\"");
  Args = SealAddText(Args,"@record",SealGetText(Args,"domain"));
  Args = SealAddText(Args,"@record","\"");

  // Add the public key if inline mode is being used
  if (SealSearch(Args,"inline"))
    {
    Args = SealAddText(Args,"@record"," pk=\"");
    Args = SealAddText(Args,"@record",SealGetText(Args,"@pubder"));
    Args = SealAddText(Args,"@record","\"");
    }

  // Add the signature!!!
  Args = SealAddText(Args,"@record"," s=\"");

  // START signature: Record local (@s) relative to this record position
  Args = SealSetIindex(Args,"@s",0,SealGetSize(Args,"@record"));

  // Encode the signature (or placeholder)
  vf = SealSearch(Args,"@signatureenc");
  if (vf)
    {
    // SealStrEncode(vf); // This better not do anything!
    Args = SealAddBin(Args,"@record",vf->ValueLen,vf->Value);
    }
  else // No signature! Use padding!
    {
    size_t DateLen=0;
    char *sf;

    // Determine date padding
    sf = SealGetText(Args,"sf");
    if (!strncmp(sf,"date",4))
      {
      DateLen += 14; // YYYYMMDDhhmmss
      Args = SealAddTextPad(Args,"@record",DateLen,"2");

      if (isdigit(sf[4])) // if there are subseconds
        {
	int subsec;
	subsec = sf[4]-'0';
        Args = SealAddC(Args,"@record",'.');
        Args = SealAddTextPad(Args,"@record",subsec,"3");
	DateLen += 1 + subsec;
	}

      Args = SealAddC(Args,"@record",':');
      DateLen++; // for the ":"
      }

    Args = SealAddTextPad(Args,"@record",(size_t)SealGetU32index(Args,"@sigsize",0)-DateLen,"abcdef");
    }

  // END signature: Record local (@s) relative to this record position
  Args = SealSetIindex(Args,"@s",1,SealGetSize(Args,"@record"));

  // End record
  Args = SealAddText(Args,"@record","\"/>");
  return(Args);
} /* SealRecord() */

