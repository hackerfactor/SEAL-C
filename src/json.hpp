/************************************************
 SEAL: implemented in C
 See LICENSE

 Handling certs: generation, signing, and verifying.
 ************************************************/
#ifndef JSON_HPP
#define JSON_HPP

// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "seal.hpp"

sealfield *	Json2Seal	(sealfield *JsonData);

#endif
