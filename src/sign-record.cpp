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

#include "seal.hpp"
#include "seal-parse.hpp"

/********************************************************
 SealRecord(): Generate the record!
 Returns: '@record' with the complete record
 NOTE: The signature is likely wrong and stubbed out.
 Use @S to fix the signature.
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
    "info",
    "copyright",
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

  // Add the signature!!!
  Args = SealAddText(Args,"@record"," s=\"");

  // START signature: Record local (@S) relative to this record position
  Args = SealSetIindex(Args,"@S",0,SealGetSize(Args,"@record"));

  // Encode the signature (or placeholder)
  vf = SealSearch(Args,"@signatureenc");
  if (vf)
    {
    // SealStrEncode(vf); // This better not do anything!
    Args = SealAddBin(Args,"@record",vf->ValueLen,vf->Value);
    }
  else // No signature! Use padding!
    {
    Args = SealAddTextPad(Args,"@record",(size_t)SealGetU32index(Args,"@sigsize",0),"abcdefghij");
    }

  // END signature: Record local (@S) relative to this record position
  Args = SealSetIindex(Args,"@S",1,SealGetSize(Args,"@record"));

  // End record
  Args = SealAddText(Args,"@record","\"/>");
  return(Args);
} /* SealRecord() */

