#include "integers.h"
#include "crypto.h"
#include <stdlib.h>

/// @brief Generates a random number of mem->size * 64 bits. Works only for linux machines (using /dev/urandom).
/// Only rule is that the bits-th bit is 1 (so that bit_length return bits)
/// @param mem pre-allocated mprec integer
/// @param bits the exact number of bits to set (above ones will be zero)
void random_number(mprec_int *mem, int bits)
{
    for (int i = 0; i < mem->size; i++)
        mem->d[i] = 0;

    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
        return;

    int total_bits = NB_BLOCKS(bits);
    for (int i = 0; i < total_bits; i++)
        fread(mem->d + i, sizeof(uint64_t), 1, f);
    fclose(f);

    for (int j = total_bits; j < mem->size; j++)
        mem->d[j] = 0;

    int leftover = bits % 64;
    if (leftover == 0)
        mem->d[total_bits - 1] |= (1UL << 63);
    else
    {
        mem->d[total_bits - 1] >>= (64 - leftover);
        mem->d[total_bits - 1] |= (1ULL << (leftover - 1));
    }
}

/// @brief Generates a random odd number. Uses [random_number].
/// @param mem
/// @param bits
void random_odd_number(mprec_int *mem, int bits)
{
    random_number(mem, bits);
    mem->d[0] |= 1;
}

/// @brief Applies miller-rabin primality testing for k rounds.
/// @param num
/// @param k
/// @return true if it is a potential prime. False otherwise.
bool miller_rabin(mprec_int *num, int k)
{
}