/************************************************
 SEAL: implemented in C

 Functions for handling manual signing.
 (Assumes you know what you are doing!)
 This is mostly for debugging.

 Some places where SEAL records can be stored are
 not directly supported for writing by sealtool.

 BUT! You can use manual mode to sign them!
 1. Generate the SEAL record:
    -M ''
 2. Manually insert the record into the file, wherever you want.
 3. Verify the file using -v
    This will display the digest value.
    Ignore the double digest!
 4. Sign the digest!
    E.g., if the digest is abcd1234 then:
      For local signing:  -m 'abcd1234'
      For remote signing: -M 'abcd1234'
    This will display the SEAL record with the signature.
 5. Manual copy the signature into your file.
 6. Verify the file again to make sure the signature is correct.
 ************************************************/
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <endian.h> // for MPF endian

#include "seal.hpp"
#include "files.hpp"
#include "seal-parse.hpp"
#include "sign.hpp"

/**************************************
 Seal_Manual(): Process manual signing.
 **************************************/
sealfield *	Seal_Manual	(sealfield *Args)
{
  sealfield *digest;

  Args = SealRecord(Args);

  digest = SealSearch(Args,"@digest1");
  if (digest)
    {
    // sign it
    switch(SealGetCindex(Args,"@mode",0)) // sign it
	{
	// Only called with -M or -m
	case 'M': Args = SealSignURL(Args); break;
	case 'm': Args = SealSignLocal(Args); break;
	default: break; // never happens
	}
    }

  printf("%s\n",SealGetText(Args,"@record"));
  return(Args);
} /* Seal_Manual() */

