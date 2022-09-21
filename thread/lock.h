#pragma once

enum STATUS { FREE, LOCK };

#ifdef __cplusplus
extern "C" {
#endif
void lock(unsigned int*);
void unlock(unsigned int*);
#ifdef __cplusplus
}
#endif