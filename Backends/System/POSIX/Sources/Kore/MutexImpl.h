#pragma once

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	pthread_mutex_t mutex;
} Kinc_MutexImpl;
	
typedef struct {

} Kinc_UberMutexImpl;

#ifdef __cplusplus
}
#endif
