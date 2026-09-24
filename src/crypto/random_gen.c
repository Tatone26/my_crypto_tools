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
    INTEGER_STACK_ALLOC(nminusone, num->size * 64);
    U64_TO_MPREC(one, 1);
    int_sub(&nminusone, num, &one);

    // get s and d for miller
    int s = 0;
    for (int i = 0; i < nminusone.size * 64; i++)
        if (int_bit_check(&nminusone, i))
        {
            s = i;
            break;
        }
    INTEGER_STACK_ALLOC(d, num->size * 64);
    int_rshift(&d, &nminusone, s);

    INTEGER_STACK_ALLOC(a, num->size * 64);
    INTEGER_STACK_ALLOC(x_m, num->size * 64);
    INTEGER_STACK_ALLOC(temp_m, num->size * 64);

    U64_TO_MPREC(two, 2);

    mprec_int *x = &x_m;
    mprec_int *temp = &temp_m;

    for (int i = 0; i < k; i++)
    {
        random_number(&a, a.size * 64);

        int_exp_mod(x, &a, &d, num);

        if (int_cmp(&one, x) == 0 || int_cmp(&nminusone, x) == 0)
            continue;

        bool cont = false;
        for (int j = 0; j < s - 1; j++)
        {
            int_exp_mod(temp, x, &two, num);
            if (int_cmp(temp, &nminusone) == 0)
            {
                cont = true;
                break;
            }
            mprec_int *t = x;
            x = temp;
            temp = t;
        }
        if (cont)
            continue;

        return false;
    }
    return true;
}

#define MILLER_RABIN_REPEATS 40
void random_prime(mprec_int *m, int bits)
{
    do
    {
        random_odd_number(m, bits);
    } while (!miller_rabin(m, MILLER_RABIN_REPEATS));
}