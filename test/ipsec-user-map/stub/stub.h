/* Stand-ins for the OpenSIPS core, so that ipsec_user.c runs on its own:
 * process memory instead of shared memory, no locks, no logging. Included
 * after the real headers and before ipsec_user.c. */
#include <stdlib.h>
#include <stdio.h>

#undef shm_malloc
#undef shm_realloc
#undef shm_free
/* ipsec_user.c has a local variable called free */
static inline void stub_free(void *p) { free(p); }
#define shm_malloc malloc
#define shm_realloc realloc
#define shm_free stub_free

#undef lock_init
#undef lock_destroy
#undef lock_get
#undef lock_release
#define lock_init(_l) (_l)
#define lock_destroy(_l)
#define lock_get(_l)
#define lock_release(_l)

#undef is_printable
#undef LM_DBG
#undef LM_ERR
#undef LM_BUG
#define is_printable(_l) 0
#define LM_DBG(...)
#define LM_ERR(...) fprintf(stderr, __VA_ARGS__)
#define LM_BUG(...) do { fprintf(stderr, __VA_ARGS__); abort(); } while (0)
