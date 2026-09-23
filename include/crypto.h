#ifndef CRYPTO_H
#define CRYPTO_H

#include "integers.h"

void random_number(mprec_int *mem, int bits);
void random_odd_number(mprec_int *mem, int bits);
bool miller_rabin(mprec_int *num, int k);

#endif