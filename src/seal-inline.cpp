/************************************************
 SEAL: implemented in C
 See LICENSE

 Processing inline public key settings.
  pk=     :: a public key (also refered to as 'p' when in the dns entry in non inline format)
  pka=    :: algorithim used to generate the pkd
  pkd=    :: digest of the public key
  dnsfile=:: path to local dns file for retrieving the public key

  pk is set in the order of precedence of commandline > dnsfile > dns
 ************************************************/
// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "sign.hpp"

/********************************************************
 SealGetPublicKey(): Get the public key for inline signing
 and set it in the pk field.
 ********************************************************/
sealfield *	SealGetPublicKey	(sealfield *Args)
{
  char *pk;
  // Nothing to do if not inline format, or pk is already defined via command line parameter
  if(!SealSearch(Args,"inline") || SealGetText(Args, "pk")) {return Args; }

  //different names are used in different places, so setting the correct variable here
  Args = SealSetText(Args, "d", SealGetText(Args, "domain"));

  // Get public key from DNS
  // it has the same precedence order
  Args = SealGetDNS(Args);

  // Check if public key was found
  pk = SealGetText(Args, "@public");
  if(!pk)
    {
    printf("    ERROR: Unable to retrieve public key for inline signing.\n");
    printf("%s\n", SealGetText(Args,"dnsfile"));
        printf("    %s\n", SealGetText(Args,"@error"));
    exit(0x80);
    } 
  Args = SealSetText(Args, "pk", pk);
  return Args;
}