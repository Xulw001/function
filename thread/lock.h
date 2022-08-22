#pragma once

enum STATUS { LOCK, FREE };

#ifdef __cplusplus
extern "C" {
#endif
void lock(unsigned int*);
void unlock(unsigned int*);
#ifdef __cplusplus
}
#endif