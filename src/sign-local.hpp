/************************************************
 SEAL: implemented in C
 See LICENSE

 Handling certs: generation, signing, and verifying.
 ************************************************/
#ifndef SIGN_LOCAL_HPP
#define SIGN_LOCAL_HPP

// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "seal.hpp"
#include "files.hpp"

#include <openssl/evp.h>

// For key generation
void	SealGenerateKeys	(sealfield *Args);
void	PrintDNSstring	(FILE *fp, const char *Label, sealfield *vf);

// For key management
void	SealFreePrivateKey	();
EVP_PKEY *	SealLoadPrivateKey	(sealfield *Args);

bool	SealIsLocal	(sealfield *Args);
sealfield *	SealSignLocal	(sealfield *Args);


#endif
