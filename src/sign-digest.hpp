/************************************************
 SEAL: implemented in C
 See LICENSE

 Handling certs: generation, signing, and verifying.
 ************************************************/
#ifndef SIGN_DIGEST_HPP
#define SIGN_DIGEST_HPP

// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "seal.hpp"
#include "files.hpp"

sealfield *	SealDigest	(sealfield *Rec, mmapfile *Mmap);
sealfield *	SealDoubleDigest	(sealfield *Rec);

#endif
