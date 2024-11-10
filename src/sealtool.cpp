/************************************************
 SEAL: implemented in C
 See LICENSE

 Main program.
 ************************************************/
// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h> // UINT_MAX
#include <ctype.h> // isalnum
#include <string.h> // memset
#include <getopt.h> // getopt()
#include <sys/types.h> // stat()
#include <sys/stat.h> // stat()
#include <libgen.h> // dirname(), basename()
#include <termios.h> // for reading password
#include <fcntl.h>
#ifndef __WIN32__
  #include <sys/mman.h> /* for mmap() */
#endif

// For openssl usage
#include <openssl/evp.h>

#include "seal.hpp"
#include "files.hpp"
#include "formats.hpp"
#include "seal-parse.hpp"
#include "sign.hpp"

/**************************************
 ReadCfg(): Read the config file.
 A config file can overwrite any already-known parameters.
 **************************************/
sealfield *	ReadCfg	(sealfield *Args)
{
  char *fname;
  FILE *fp;
  int c,b;
  int fieldlen,valuestart,valueend;
  /*****
   Finite state machine states
   0=read field
   1=read padding to =
   2=read padding after =
   3=read value
   4=ignore line (comment)
   *****/
  int LineNo,state;
  char Buf[1024]; // no more than 1K per line

  fname = SealGetText(Args,"config");
  if (!fname) { return(Args); }
  if (access(fname, F_OK) != 0) // if file does not exist
    {
    return(Args);
    }

  fp=fopen(fname,"r");
  if (!fp)
    {
    fprintf(stderr,"ERROR: Unable to read configuration file: '%s'\n",fname);
    exit(1);
    }

  /* Read the file */
  b=0;
  memset(Buf,0,1024);
  state = fieldlen = valuestart = valueend = 0;
  LineNo=1;
  while((c=fgetc(fp)) >= 0)
    {
    if (b > 1024)
	{
	fprintf(stderr,"ERROR: configuration file line too long: line %d in '%s'\n",LineNo,fname);
	exit(1);
	}

    if (c=='\n') // end of line!
	{
	// check for valid line
	if (state==4) { ; } // comment
	else if ((state==0) && (b==0)) { ; } // blank line
	else if (state==3) // good field/value
	  {
	  Buf[fieldlen]='\0'; // null-terminate field name
	  if (SealGetText(Args,Buf)==NULL)
	    {
	    fprintf(stderr,"ERROR: unknown field '%.*s': line %d in '%s'\n",fieldlen,Buf,LineNo,fname);
	    exit(1);
	    }
	  //fprintf(stderr,"DEBUG: Line[%d] field='%.*s' value='%.*s'\n",LineNo,fieldlen,Buf,valueend-valuestart,Buf+valuestart);
	  Args=SealSetText(Args,Buf,Buf+valuestart);
	  }
	else // unknown line format
	  {
	  fprintf(stderr,"ERROR: configuration file bad format: line %d in '%s'\n",LineNo,fname);
	  exit(1);
	  }

	// Reset for next line
	LineNo++;
	b=0;
	memset(Buf,0,1024);
	state = fieldlen = valuestart = valueend = 0;
	state=0;
	}

    if (state==4) { ; } // ignore it

    if (state==0) // reading field name
	{
	if ((b==0) && (c=='#')) { state=4; continue; } // comment
	if ((b==0) && isspace(c)) { continue; } // skip initial spaces
	if ((b==0) && !isalnum(c)) // bad start
	  {
	  fprintf(stderr,"ERROR: configuration file bad initial character: line %d in '%s'\n",LineNo,fname);
	  exit(1);
	  }
	if (isalnum(c))
	  {
	  Buf[b]=c; b++;
	  fieldlen++;
	  }
	else if (isspace(c))
	  {
	  Buf[b]=c; b++;
	  state=1;
	  continue;
	  }
	else if (c=='=')
	  {
	  Buf[b]=c; b++;
	  state=2;
	  continue;
	  }
	}

    if (state==1) // reading space before "="
	{
	if (isspace(c)) { ; } // skip it
	else if (c=='=') // Got separator!
	  {
	  Buf[b]=c; b++;
	  state=2;
	  continue;
	  }
	}

    if (state==2) // reading space after "="
	{
	if (isspace(c)) { ; } // skip it
	else // Got start of value!
	  {
	  valuestart=b;
	  state=3; // fall through to reading value
	  }
	}

    if (state==3) // reading value
	{
	Buf[b]=c; b++;
	if (!isspace(c)) { valueend=b; }
	}
    }

  fclose(fp);
  return(Args);
} /* ReadCfg() */

/**************************************
 print_km_name(): Callback for OpenSSL listing key algorithms
 **************************************/
void	print_km_name	(const char *name, void *param)
{
  if (name && !isdigit(name[0]) && !strstr(name,"-old") && !strchr(name,' '))
    {
    printf("        %s\n",name);
    }
} /* print_km_name() */

/**************************************
 print_km(): Callback for OpenSSL listing key algorithms
 **************************************/
void	print_km	(EVP_KEYMGMT *km, void *param)
{
  EVP_KEYMGMT_names_do_all(km, print_km_name, NULL);
} /* print_km() */

/**************************************
 Usage(): Show usage and abort.
 **************************************/
void	Usage	(const char *progname)
{
  printf("Usage: %s [options] file [file...]\n",progname);
  printf("  -h, -?, --help    :: Show help; this usage\n");
  printf("  --config file.cfg :: Optional configuration file (default: $HOME/.seal.cfg)\n");
  printf("  -v                :: Verbose debugging (probably not what you want)\n");
  printf("  -V, --version     :: Show the code version and exit.\n");
  printf("\n");
  printf("  Verifying:\n");
  printf("  Verify any SEAL signature in the file(s)\n");
  printf("  -D, --dnsfile fname  :: Optional: text file with DNS TXT value. (default: unset; use DNS)\n");
  printf("  --dnsfile1 fname  :: Debugging: use this text file with DNS TXT value.\n");
  printf("\n");
  printf("  Generate signature:\n");
  printf("  -g, --generate       :: Required: generate a signature\n");
  printf("  -D, --dnsfile fname  :: File for storing the public key for DNS (default: ./seal-public.dns)\n");
  printf("  -k, --keyfile fname  :: File for storing the private key in PEM format (default: ./seal-private.pem)\n");
  // NIST Approved: P-256 = prime256v1; default if you say "ec"
  // NIST Approved: P-384 = secp384r1
  printf("  -K, --keyalg alg     :: Key algorithm (rsa, ec, P-256; default: rsa)\n");
  // EVP_KEYMGMT_do_all_provided(NULL, print_km, NULL);
  printf("  --kv number          :: Unique key version (default: 1)\n");
  printf("  --uid text           :: Unique key identifier (default: not set)\n");
  printf("\n");
  printf("  Signing with a local private key:\n");
  printf("  -s, --sign           :: Required: Enable signing (requires lowercase 's')\n");
  printf("  -k, --keyfile fname  :: File for storing the private key in PEM format (default: ./seal-private.pem)\n");
  printf("\n");
  printf("  Signing with a remote signing service:\n");
  printf("  -S, --Sign           :: Required: Enable signing (requires uppercase 'S')\n");
  printf("  -u, --apiurl url     :: For remote signers (default: no url)\n");
  printf("  -a, --apikey id      :: For remote signers (default: no API key)\n");
  printf("  -i, --id id          :: User-specific identifier (default: no identifier)\n");
  printf("  --cacert file.crl    :: Use file.crl for trusted root certificates.");
#ifdef __CYGWIN__
  printf(" (default: ./cacert.crl)");
#else
  printf(" (default: unset; uses operating system defaults)");
#endif
  printf("\n");
  printf("  --cert-insecure      :: Do not validate server's TLS certificate.\n");
  printf("\n");
  printf("  Manual signing: (mostly for debugging; probably not what you want)\n");
  printf("  -M, --Manual ''      :: Generate the SEAL record with a stubbed value.\n");
  printf("  -M, --Manual digest  :: Given a hex digest, sign it using a remote service.\n");
  printf("  -m, --manual digest  :: Given a hex digest, sign it using a local key.\n");
  printf("\n");
  printf("  Common signing options (for local and remote)\n");
  printf("  -d, --domain domain  :: DNS entry with the public key (default: localhost.localdomain)\n");
  printf("  -o, --outfile fname  :: Output filename\n");
  printf("               Include '%%d' for directory name without final /\n");
  printf("               Include '%%b' for base filename\n");
  printf("               Include '%%e' for filename extension, including '.'\n");
  printf("               Include '%%%%' for a percent sign\n");
  printf("               Default: './%%b-seal%%e'\n");
  printf("  -O, --options  text  :: Signing-specific options (default: none)\n");
  printf("        -O text may contain a comma-separated list of options:\n");
  printf("        append  :: This is an appending signature; not final signature.\n");
  printf("        seAl,SEAL,teXt,tEXt,...  :: PNG: chunk name to use.\n");
  printf("  -K, --keyalg alg     :: Key algorithm  (default: rsa)\n");
  printf("  -A, --digestalg alg    :: Digest (hash) algorithm  (default: sha256)\n");
  printf("               Supports: sha224, sha256, sha384, sha512\n");
  printf("  -C, --copyright text :: Copyright text (default: no added text)\n");
  printf("  -c, --comment text   :: Informational/comment text (default: no added text)\n");
  printf("  --kv number          :: Unique key version (default: 1)\n");
  printf("  --sf text            :: Signing format (default: HEX)\n");
  exit(1);
} /* Usage() */

/**************************************
 main()
 **************************************/
int main (int argc, char *argv[])
{
  sealfield *Args=NULL, *CleanArgs;
  int c;
  int Mode='v';
  int FileFormat='@';
  bool IsURL=false; // for signing, use URL?
  bool IsLocal=false; // for signing, use local?

  // Set default values
  Args = SealSetText(Args,"seal","1"); // SEAL version; currently always '1'
  Args = SealSetText(Args,"b","F~S,s~f"); // default byte range is everything
  Args = SealSetText(Args,"digestalg","sha256");
  Args = SealSetText(Args,"keyalg","rsa");
  Args = SealSetText(Args,"keybits","2048");
  Args = SealSetText(Args,"keyfile","./seal-private.pem");
  Args = SealSetText(Args,"outfile","./%b-seal%e");
  Args = SealSetText(Args,"options","");
  Args = SealSetText(Args,"kv","1");
  Args = SealSetText(Args,"sf","HEX");
  Args = SealSetText(Args,"domain","localhost.localdomain");
  Args = SealSetText(Args,"dnsfile","");
  Args = SealSetText(Args,"copyright","");
  Args = SealSetText(Args,"comment","");
  Args = SealSetText(Args,"info","");
  Args = SealSetText(Args,"id","");
  Args = SealSetText(Args,"apiurl","");
  Args = SealSetText(Args,"apikey","");
#ifdef __CYGWIN__
  Args = SealSetText(Args,"cacert","./cacert.crt");
#endif

  // Set default config file based on user's home.
  Args = SealSetText(Args,"config",getenv("HOME"));
  Args = SealAddText(Args,"config","/.seal.cfg");
  Args = ReadCfg(Args);

  // p and s are used with b to generate the hash.
  Args = SealSetIindex(Args,"@s",2,0); // sig offset in file [0]=start, [1]=end, [2]=number of signatures; default:zeros
  Args = SealSetIindex(Args,"@p",1,0); // previous sig offset in file [0]=start, [1]=end; default:[0,0]
  Args = SealSetCindex(Args,"@sflags",2,0); // Flags: [0] has 'F', [1] has 'f'; set by SealDigest()

  // Read command-line
  int long_option_index;
  struct option long_options[] = {
    // Options match https://github.com/hackerfactor/SEAL/blob/master/SPECIFICATION.md
    {"help",      no_argument, NULL, 'h'},
    {"verbose",   no_argument, NULL, 'v'},
    {"version",   no_argument, NULL, 'V'},
    {"config",    required_argument, NULL, 9},
    {"generate",  no_argument, NULL, 'g'},
    {"genpass" ,  no_argument, NULL, 'G'},
    {"da",        required_argument, NULL, 'A'},
    {"digestalg", required_argument, NULL, 'A'},
    {"dnsfile1", required_argument, NULL, 'P'}, // Debugging: specify dns via command-line
    {"apikey",    required_argument, NULL, 'a'},
    {"apiurl",    required_argument, NULL, 1},
    {"cacert",    required_argument, NULL, 1}, // for specifying root PEMs
    {"cert-insecure", no_argument, NULL, 0}, // for ignoring TLS verification
    {"comment",   required_argument, NULL, 'c'},
    {"copyright", required_argument, NULL, 'C'},
    {"dnsfile",   required_argument, NULL, 'D'},
    {"domain",    required_argument, NULL, 'd'},
    {"id",        required_argument, NULL, 'i'},
    {"ka",        required_argument, NULL, 'K'},
    {"keyalg",    required_argument, NULL, 'K'},
    {"keybits",   required_argument, NULL, 1},
    {"keyfile",   required_argument, NULL, 'k'},
    {"Manual",    required_argument, NULL, 'M'},
    {"manual",    required_argument, NULL, 'm'},
    {"outfile",   required_argument, NULL, 'o'},
    {"options",   required_argument, NULL, 'O'},
    {"Sign",      no_argument, NULL, 'S'},
    {"sign",      no_argument, NULL, 's'},
    // long-only options
    {"sf",        required_argument, NULL, 1},
    {"kv",        required_argument, NULL, 1}, // must be numeric >= 0
    {"uid",       required_argument, NULL, 1},
    // modes
    {NULL,0,NULL,0}
    };
  while ((c = getopt_long(argc,argv,"A:a:C:c:D:d:ghi:K:k:M:m:o:O:Ssu:VvW?",long_options,&long_option_index)) != -1)
    {
    switch(c)
      {
      case 0: // generic longopt with no_argument
	Args = SealSetText(Args,long_options[long_option_index].name,"1");
	break;
      case 1: // generic longopt with required_argument (and no single-letter mapping)
	Args = SealSetText(Args,long_options[long_option_index].name,optarg);
	break;
      case 9: // read configuration file
	Args = SealSetText(Args,"config",optarg);
	Args = ReadCfg(Args);
	break;
      case 'A': Args = SealSetText(Args,"digestalg",optarg); break;
      case 'a': Args = SealSetText(Args,"apikey",optarg); break;
      case 'C': Args = SealSetText(Args,"copyright",optarg); break;
      case 'c': Args = SealSetText(Args,"info",optarg); break;
      case 'D': Args = SealSetText(Args,"dnsfile",optarg); break;
      case 'd': Args = SealSetText(Args,"domain",optarg); break;
      case 'i': Args = SealSetText(Args,"id",optarg); break;
      case 'K': Args = SealSetText(Args,"keyalg",optarg); break;
      case 'k': Args = SealSetText(Args,"keyfile",optarg); break;
      case 'P': Args = SealSetText(Args,"@dnsfile1",optarg); break; // for debugging
      case 'o': Args = SealSetText(Args,"outfile",optarg); break;
      case 'O': Args = SealSetText(Args,"options",optarg); break;
      case 'u': Args = SealSetText(Args,"apiurl",optarg); break;

      case 'G': // generate password (not in usage; really insecure)
	Args = SealSetText(Args,"@genpass",optarg); break;

      case 'M': // manual remote signing
      case 'm': // manual local signing
	{
	if (optarg[0])
	  {
	  Args = SealSetText(Args,"@digest1",optarg);
	  SealHexDecode(SealSearch(Args,"@digest1")); // hex to binary
	  }
	}
	// fall through to Mode check
      case 'g': // generate flag
      case 'S': // signing flag: remote
      case 's': // signing flag: local
	if (Mode!='v') // if it's not the default value...
	  {
	  fprintf(stderr,"ERROR: Only one -g, -s, -S, -m, or -M permitted\n");
	  exit(1);
	  }
	Mode=c;
	break;

      case 'V': printf("%s\n",SEAL_VERSION); exit(0);
      case 'v': Verbose++; break;

      case 'W': // write the data as a config file
	{
	char *s;
	printf("# Generating signature options\n");
	s=SealGetText(Args,"dnsfile"); if (s && s[0]) { printf("dnsfile=%s\n",s); } else { printf("#dnsfile=\n"); }
	s=SealGetText(Args,"uuid"); if (s && s[0]) { printf("uuid=%s\n",s); } else { printf("#uuid=\n"); }
	printf("\n");
	printf("# Local signing options (for use with -s)\n");
	printf("keyfile=%s\n",SealGetText(Args,"keyfile"));
	printf("\n");
	printf("# Remote signing options (for use with -S)\n");
	s=SealGetText(Args,"apiurl"); if (s && s[0]) { printf("apiurl=%s\n",s); } else { printf("#apiurl=\n"); }
	s=SealGetText(Args,"apikey"); if (s && s[0]) { printf("apikey=%s\n",s); } else { printf("#apikey=\n"); }
	s=SealGetText(Args,"id"); if (s && s[0]) { printf("id=%s\n",s); } else { printf("#id=\n"); }
	printf("\n");
	printf("# Common signing options (for use with -s or -S)\n");
	printf("domain=%s\n",SealGetText(Args,"domain"));
	printf("digestalg=%s\n",SealGetText(Args,"digestalg"));
	printf("keyalg=%s\n",SealGetText(Args,"keyalg"));
	printf("kv=%s\n",SealGetText(Args,"kv"));
	printf("sf=%s\n",SealGetText(Args,"sf"));
	s=SealGetText(Args,"info"); if (s && s[0]) { printf("comment=%s\n",s); } else { printf("#comment=\n"); }
	s=SealGetText(Args,"copyright"); if (s && s[0]) { printf("copyright=%s\n",s); } else { printf("#copyright=\n"); }
	printf("outfile=%s\n",SealGetText(Args,"outfile"));
	printf("\n");
	exit(0);
	}
	break;
      case 'h': // help
      case '?': // help
      default:  Usage(argv[0]); SealFree(Args); exit(1);
      }
    } // while reading args

  // Idiot check values: No double-quotes!
  Args = SealParmCheck(Args);
  IsURL = SealIsURL(Args);
  IsLocal = SealIsLocal(Args);

  if (Mode=='g') // if generating keys
    {
    if (!SealSearch(Args,"dnsfile"))
	{
	Args = SealSetText(Args,"dnsfile","./seal-public.dns");
	}
    SealGenerateKeys(Args);
    return(0); // done processing
    }

  // If signing, get dynamic signing parameters
  if (strchr("sSmM",Mode))
    {
    /*****
     When signing, no digest gets the size of the signature (@sigsize).
     This never changes between calls, so do it now.
     *****/
    if (IsURL && strchr("SM",Mode)) { Args = SealSignURL(Args); }
    else if (IsLocal && strchr("sm",Mode)) { Args = SealSignLocal(Args); }
    // Must have sigsize!
    if (SealGetU32index(Args,"@sigsize",0)==0)
	{
	fprintf(stderr,"ERROR: Unable to determine the signature size. Aborting.\n");
	exit(1);
	}
    Args = SealSetCindex(Args,"@mode",0,Mode);
    }
  else
    {
    Args = SealSetText(Args,"Mode","verify");
    }
  if (Verbose > 3) { DEBUGWALK("Post-CLI Parameters",Args); } // DEBUGGING

  // Manual processing (no files)
  if (strchr("Mm",Mode))
    {
    Seal_Manual(Args);
    return(0); // done processing
    }

  // Process all args (files required)
  if (optind >= argc)
    {
    fprintf(stderr,"ERROR: No input files.\n");
    exit(1);
    }

  // Don't mess up command-line parameters
  CleanArgs = Args;
  Args=NULL;

  // Process command-line files.
  bool First=true;
  for( ; optind < argc; optind++)
    {
    // Start off with a clean set of parameters
    if (Args) { SealFree(Args); Args=NULL; }
    Args = SealClone(CleanArgs);

    // Show file being processed.
    if (First) { First=false; } else { printf("\n"); }
    printf("[%s]\n",argv[optind]);
    fflush(stdout);

    // Memory map the file; needed for finding the SEAL record's location.
    mmapfile *Mmap=NULL;
    Mmap = MmapFile(argv[optind],PROT_READ); // read-only
    if (!Mmap)
	{
	fprintf(stdout," ERROR: Unknown file '%s'. Skipping.\n",argv[optind]);
	continue;
	}

    // Identify the filename format
    if (Seal_isPNG(Mmap)) { FileFormat='P'; } // PNG
    else if (Seal_isJPEG(Mmap)) { FileFormat='J'; } // JPEG
    else if (Seal_isRIFF(Mmap)) { FileFormat='R'; } // RIFF
    else if (Seal_isMatroska(Mmap)) { FileFormat='M'; } // Matroska
    else if (Seal_isBMFF(Mmap)) { FileFormat='B'; } // BMFF
    else if (Seal_isPDF(Mmap)) { FileFormat='p'; } // PDF
    else if (Seal_isPPM(Mmap)) { FileFormat='m'; } // PPM/PGM
    else
	{
	fprintf(stdout," ERROR: Unknown file format '%s'. Skipping.\n",argv[optind]);
	MmapFree(Mmap);
	continue;
	}

    // File exists! Now process it!
    if ((Mode=='s') || // if signing from local file
        (Mode=='S')) // if signing from remote service
      {
      char *Outname, *Template;
      Template = (char*)(SealSearch(Args,"outfile")->Value);
      Outname = MakeFilename(Template,(char*)argv[optind]);
      if (!Outname) { continue; }
      Args = SealSetText(Args,"@FilenameOut",Outname);
      free(Outname);
      }

    // Process based on file format
    switch(FileFormat)
    	{
	case 'B': Args = Seal_BMFF(Args,Mmap); break; // BMFF
	case 'J': Args = Seal_JPEG(Args,Mmap); break; // JPEG
	case 'M': Args = Seal_Matroska(Args,Mmap); break; // Matroska
	case 'm': Args = Seal_PPM(Args,Mmap); break; // PPM/PGM
	case 'P': Args = Seal_PNG(Args,Mmap); break; // PNG
	case 'p': Args = Seal_PDF(Args,Mmap); break; // PDF
	case 'R': Args = Seal_RIFF(Args,Mmap); break; // RIFF
	default: break; // should never happen
	}

    if (Verbose > 1) { DEBUGWALK("Post-File Parameters",Args); } // DEBUGGING
    MmapFree(Mmap);
    if (Args) { SealFree(Args); Args=NULL; }
    } // foreach command-line file

  // Clean up
  SealFreePrivateKey(); // if a private key was allocated
  if (Args) { SealFree(Args); Args=NULL; }
  SealFree(CleanArgs); // free memory for completeness
  return(0);
} /* main() */

