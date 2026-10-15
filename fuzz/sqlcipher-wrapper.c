/* SQLCipher's configuration, heading the one unit build.rs assembles with libtomcrypt and the entropy hook. */
#define SQLITE_HAS_CODEC 1
#define SQLCIPHER_CRYPTO_LIBTOMCRYPT 1
/* Installs the entropy hook before SQLCipher's own init runs. */
#define SQLITE_EXTRA_INIT sqlcipher_wasm_extra_init
#define SQLITE_EXTRA_SHUTDOWN sqlcipher_extra_shutdown
/* SQLCipher's log needs a timestamp and a device the harness does not keep. */
#define SQLCIPHER_OMIT_LOG 1
#define SQLCIPHER_OMIT_LOG_DEVICE 1
#define OMIT_MEMLOCK 1
/* SQLCipher refuses SQLITE_THREADSAFE=0, and the harness runs single-threaded, so no-op mutexes suffice. */
#undef SQLITE_THREADSAFE
#define SQLITE_THREADSAFE 1
#define SQLITE_MUTEX_NOOP 1

#define LTC_SOURCE
#include "sqlcipher-ltc.h"
#include "sqlcipher.c"
