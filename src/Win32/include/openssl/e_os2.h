/* e_os2.h */

#ifndef HEADER_E_OS2_H
#define HEADER_E_OS2_H

#include <openssl/opensslconf.h> /* OPENSSL_UNISTD */

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef MSDOS
# define OPENSSL_UNISTD_IO <io.h>
# define OPENSSL_DECLARE_EXIT extern void exit(int);
#else
# define OPENSSL_UNISTD_IO OPENSSL_UNISTD
# define OPENSSL_DECLARE_EXIT /* declared in unistd.h */
#endif

/* Definitions of OPENSSL_GLOBAL and OPENSSL_EXTERN,
   to define and declare certain global
   symbols that, with some compilers under VMS, have to be defined and
   declared explicitely with globaldef and globalref.  On other OS:es,
   these macros are defined with something sensible. */

#if defined(VMS) && !defined(__DECC)
# define OPENSSL_EXTERN globalref
# define OPENSSL_GLOBAL globaldef
#else

/*OPENSSL_EXTERN and OPENSSL_GLOBAL need to be set differently for static buids,
  dynamic builds of the libraries, and dynamic links to the libraries*/

# ifdef OPENSSL_STATIC
#  define OPENSSL_EXTERN extern  
#  define OPENSSL_GLOBAL

# else
#  ifdef OPENSSL_BUILDING
#   define OPENSSL_EXTERN __declspec(dllexport)
#   define OPENSSL_GLOBAL __declspec(dllexport)
#  else 
#   define OPENSSL_EXTERN __declspec(dllimport)
#   define OPENSSL_GLOBAL __declspec(dllimport)
#  endif//OPENSSL_BUILDING
# endif //OPENSSL_STATIC
#endif //VMS

#ifdef  __cplusplus
}
#endif
#endif

