/************************************************
 SEAL: implemented in C
 See LICENSE

 Handling certs: generation, signing, and verifying.

 ************************************************/
#ifndef SIGN_RECORD_HPP
#define SIGN_RECORD_HPP

// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "seal.hpp"
#include "files.hpp"

sealfield *	SealRecord	(sealfield *Args);

#endif
