/************************************************
 SEAL: implemented in C
 See LICENSE

 Handling certs: generation, signing, and verifying.
 ************************************************/
#ifndef SIGN_HPP
#define SIGN_HPP

// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "seal.hpp"
#include "files.hpp"

// For key generation
void	SealGenerateKeys	(sealfield *Args);
void	PrintDNSstring	(FILE *fp, const char *Label, sealfield *vf);

// For key management
#include <openssl/evp.h>
void	SealFreePrivateKey	();
EVP_PKEY *	SealLoadPrivateKey	(sealfield *Args);

// Build a SEAL record
sealfield *	SealRecord	(sealfield *Args);

// Compute digest
sealfield *	SealDigest	(sealfield *Rec, mmapfile *Mmap);
sealfield *	SealDoubleDigest	(sealfield *Rec);

// Sign (generic)
mmapfile *	SealInsert	(sealfield *Rec, mmapfile *MmapIn, size_t InsertOffset);
bool	SealSign	(sealfield *Rec, mmapfile *MmapOut);

// Sign Local
bool	SealIsLocal	(sealfield *Args);
sealfield *	SealSignLocal	(sealfield *Args);

// Sign Remote
bool	SealIsURL	(sealfield *Args);
sealfield *	SealSignURL	(sealfield *Args);

// Verify
sealfield *	SealGetDNS	(sealfield *Rec);
sealfield *	SealRotateRecords	(sealfield *Rec);
sealfield *	SealVerify	(sealfield *Rec, mmapfile *Mmap);
bool	SealVerifyFinal	(sealfield *Rec);
sealfield *	SealVerifyBlock	(sealfield *Args, size_t BlockStart, size_t BlockEnd, mmapfile *Mmap);

#endif
