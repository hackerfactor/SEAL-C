/************************************************
 SEAL: implemented in C
 See LICENSE

 Parsing seal record
 ************************************************/
#ifndef SEAL_PARSE_HPP
#define SEAL_PARSE_HPP

// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "seal.hpp"

enum SealSignatureFormat{
  HEX_LOWER,
  HEX_UPPER,
  BASE64,
  BIN,
  INVALID
};

extern const char* SignatureFormats[];

sealfield *	SealParse	(size_t TextLen, const byte *Text, size_t Offset, sealfield *Args);
void	SealStrDecode	(sealfield *Data);
void	SealStrEncode	(sealfield *Data);
void	SealXmlDecode	(sealfield *Data);
void	SealXmlEncode	(sealfield *Data);
void	SealHexDecode	(sealfield *Data);
void	SealHexEncode	(sealfield *Data, bool IsUpper);
void	SealBase64Decode	(sealfield *Data);
void	SealBase64Encode	(sealfield *Data);

SealSignatureFormat SealGetSF(const char* Sf);
void	SealEncode(sealfield *data, SealSignatureFormat Sf);
void	SealDecode(sealfield *data, SealSignatureFormat Sf);

#endif
