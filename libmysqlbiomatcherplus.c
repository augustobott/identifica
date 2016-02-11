/* INSTRUCTIONS

augusto@bott.com.br - jun/2014


gcc -shared -o libmysqlbiomatcherplus.so libmysqlbiomatcherplus.c -I /opt/DigitalPersona/UareUSDK/Include/ -I /usr/include/mysql/ -ldpfpdd -ldpfj -fPIC
sudo cp libmysqlbiomatcherplus.so /usr/lib/mysql/plugin

*** COPY libdpfj.so.2 to system libs dir ***
sudo cp libdpfj.so.2 /usr/lib/

*** DISABLE AppArmor for MySQL/MariaDB or at least configure it properly! ***


CREATE FUNCTION fingerprint_dissimilarity RETURNS INTEGER SONAME 'libmysqlbiomatcherplus.so';
DROP FUNCTION fingerprint_dissimilarity;

http://marcusthorman.blogspot.com.br/2012/01/creating-simple-string-reversing-user.html
https://github.com/megastep/mysql-udf/blob/master/udf_median.cc
http://stackoverflow.com/questions/18229938/udf-result-error

SELECT pessoa_id, fingerprint_dissimilarity(x'464d52002.........', unhex(minucia)) AS res FROM dados_biometricos order by res asc limit 10;

* 0 = no false positives
* maxint (#7FFFFFFF or 2147483647) = fingerprints do not match at all

Your Threshold
Corresponding False Positive Identification Rate 
Expected number of False Positive Identifications 
Numeric Value of Threshold
.001 * maxint       .1%   1 in 1,000     2147483
.0001 * maxint     .01%   1 in 10,000     214748
.00001 * maxint   .001%   1 in 100,000     21474
1.0e-6 * maxint  .0001%   1 in 1,000,000    2147

*/

#ifdef STANDARD
/* STANDARD is defined, don't use any mysql functions */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef __WIN__
typedef unsigned __int64 ulonglong; /* Microsofts 64 bit types */
typedef __int64 longlong;
#else
typedef unsigned long long ulonglong;
typedef long long longlong;
#endif /*__WIN__*/

#else /*STANDARD*/

#include <my_global.h>
#include <my_sys.h>

#if defined(MYSQL_SERVER)
#include <m_string.h> /* To get strmov() */
#else
/* when compiled as standalone */
#include <string.h>
#define strmov(a,b) stpcpy(a,b)
#define bzero(a,b) memset(a,0,b)
#define memcpy_fixed(a,b,c) memcpy(a,b,c)
#endif /*defined(MYSQL_SERVER)*/

#endif /*STANDARD*/

#include <mysql.h>
#include <ctype.h>
#include <dpfj.h>
#include <dpfpdd.h>

/* Target accuracy of fingerprint comparison */
#define TARGET_FALSEMATCH_RATE (DPFJ_PROBABILITY_ONE / 100000)

#ifdef HAVE_DLOPEN

#if !defined(HAVE_GETHOSTBYADDR_R) || !defined(HAVE_SOLARIS_STYLE_GETHOST)
static pthread_mutex_t LOCK_hostname;
#endif

#include <math.h>

my_bool fingerprint_dissimilarity_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if ((args->arg_count != 2)) {
    strcpy(message, "Expected two arguments (minutia, minutia)");
    return 1;
  }
  return 0;
}

void fingerprint_dissimilarity_deinit(UDF_INIT *initid __attribute__((unused))) {
}

int VerifyUser( unsigned char* dbPrint, unsigned int dbPrintSize, unsigned char* print, unsigned int printSize) {
  /* Only compare if both fingerprints have data */
  if (dbPrintSize > 0 && printSize > 0) {
    unsigned int falsematch_rate;
/* COMPARES ISO MINUTIAE */
    int result = dpfj_compare(DPFJ_FMD_ISO_19794_2_2005, dbPrint, dbPrintSize, 0, DPFJ_FMD_ANSI_378_2004, print, printSize, 0, &falsematch_rate);
/* USE THIS TO COMPARE ANSI MINUTIAE */
/*
    int result = dpfj_compare(DPFJ_FMD_ANSI_378_2004, dbPrint, dbPrintSize, 0, DPFJ_FMD_ANSI_378_2004, print, printSize, 0, &falsematch_rate);
*/

    /* If the comparison was successful and the prints matched */
//    if (result == DPFJ_SUCCESS && falsematch_rate < TARGET_FALSEMATCH_RATE) {
    if (result == DPFJ_SUCCESS) {
        return falsematch_rate;
    }
  }
  return -1;
}

int fingerprint_dissimilarity(UDF_INIT* initid, UDF_ARGS* args __attribute__((unused)), char* is_null __attribute__((unused)), char* error __attribute__((unused))) {
  unsigned char *arg0;
  arg0 = args->args[0];
  unsigned long length0 = args->lengths[0];
  unsigned char *arg1;
  arg1 = args->args[1];
  unsigned long length1 = args->lengths[1];
//  unsigned long target_falsematch_rate;

/*  if ((args->arg_count == 3)) {*/
/*    target_falsematch_rate = *((unsigned long *) args->args[2]);*/
/*  } else {*/
/*    target_falsematch_rate = TARGET_FALSEMATCH_RATE;*/
/*  }*/

//  return VerifyUser( arg0, length0, arg1, length1, target_falsematch_rate);
  return VerifyUser( arg0, length0, arg1, length1);
}

#endif /* HAVE_DLOPEN */

