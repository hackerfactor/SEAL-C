/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for converting between sealvalue and json.
 ************************************************/
// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "seal.hpp"
#include "json.hpp"

// Why build my own when I can use an existing library?
// https://github.com/DaveGamble/cJSON
// cJSON is MIT license.
#include "cJSON/cJSON.h"
#include "cJSON/cJSON.c"

/**************************************
 Json2Seal(): Convert json to seal.
 Json must be a sealfield* with the Field and Value set.
 Caller must use SealFree().
 Returns: sealfield* or NULL if invalid.
 **************************************/
sealfield *	Json2Seal	(sealfield *JsonData)
{
  sealfield *SF=NULL;

  if (!JsonData || !JsonData->Field || (JsonData->ValueLen < 5)) { return(NULL); }

  /*****
   json provides a field=value
   SEAL's json is never nested, so it only needs to scan the top-level JSON.
   *****/
  struct cJSON *json, *jnext;
  json = cJSON_ParseWithLength((char*)JsonData->Value,JsonData->ValueLen);
  if (!json) { return(NULL); }

  for(jnext=json->child; jnext; jnext = jnext->next)
    {
    switch(jnext->type)
      {
      case cJSON_False: SF=SealSetU32index(SF,jnext->string,0,0); break;
      case cJSON_True: SF=SealSetU32index(SF,jnext->string,0,1); break;
      case cJSON_String: SF=SealSetText(SF,jnext->string,jnext->valuestring); break;
      case cJSON_Number:
        {
        // SEAL only uses positive integers
	if (jnext->valueint >= 0)
	  {
          SF=SealSetU32index(SF,jnext->string,0,jnext->valueint);
	  }
	// else: skip unknown
	break;
	}
      default:
	// skip unknown
	break;
      }
    }

  // clean up
  cJSON_Delete(json);
  // If nothing was set, then SF is NULL.
  return(SF);
} /* Json2Seal() */

