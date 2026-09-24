/**
 * This file contains the simplest functions for multi-precision algorithm : comparison, shifts, add/sub, mult.
 * More complicated ones like modular operations or division can be found in other files.
 */

#include "integers.h"

/// @brief Compares two integers
/// @param a integer 1
/// @param b integer 2
/// @return -1 if a < b, 0 if a == b and 1 if a > b
int int_cmp(const mprec_int *a, const mprec_int *b)
{
    if (!a || !b)
        return 0;

    int max_n = a->size > b->size ? a->size : b->size;
    int min_n = a->size > b->size ? b->size : a->size;

    if (max_n != min_n)
    {
        if (a->size == max_n)
        {
            for (int j = max_n - 1; j >= min_n; j--)
            {
                if (a->d[j] != 0)
                    return 1;
            }
        }
        else
        {
            for (int j = max_n - 1; j >= min_n; j--)
            {
                if (b->d[j] != 0)
                    return -1;
            }
        }
    }

    for (int i = min_n - 1; i >= 0; i--)
    {
        uint64_t a_v = a->d[i];
        uint64_t b_v = b->d[i];
        if (a_v < b_v)
            return -1;
        if (a_v > b_v)
            return 1;
    }

    return 0;
}

/// @brief Adds two mprec integers into r
/// @param r Destination (cleared to 0)
/// @param a integer 1
/// @param b integer 2
/// @return Final carry out-of-bounds, or (uint64_t)-1 on error
uint64_t int_add(mprec_int *r, const mprec_int *a, const mprec_int *b)
{
    if (!r || !a || !b || !r->d || !a->d || !b->d)
        return (uint64_t)-1;

    int min_size = (a->size < b->size ? a->size : b->size);
    int max_size = (a->size > b->size ? a->size : b->size);
    if (r->size < max_size)
        return (uint64_t)-1;

    // Reset destination to 0
    memset(r->d, 0, (size_t)r->size * sizeof(uint64_t));

    unsigned long c = 0;
    for (int i = 0; i < min_size; i++)
        r->d[i] = __builtin_addcl(a->d[i], b->d[i], c, &c);

    if (a->size > min_size)
        for (int i = min_size; i < a->size; i++)
            r->d[i] = __builtin_addcl(a->d[i], 0, c, &c);

    if (b->size > min_size)
        for (int i = min_size; i < b->size; i++)
            r->d[i] = __builtin_addcl(b->d[i], 0, c, &c);

    if (max_size < r->size)
    {
        r->d[max_size] = c;
        c = 0;
    }

    return (uint64_t)c;
}

/// @brief Removes b from a into r (r = a - b)
/// @param r Destination (cleared to 0)
/// @param a integer 1
/// @param b integer 2
/// @return Final borrow (underflow flag), or (uint64_t)-1 on error
uint64_t int_sub(mprec_int *r, const mprec_int *a, const mprec_int *b)
{
    if (!r || !a || !b || !r->d || !a->d || !b->d)
        return (uint64_t)-1;

    int min_size = (a->size < b->size ? a->size : b->size);
    int max_size = (a->size > b->size ? a->size : b->size);
    if (r->size < max_size)
        return (uint64_t)-1;

    // Reset destination to 0
    memset(r->d, 0, (size_t)r->size * sizeof(uint64_t));

    unsigned long borrow = 0;
    for (int i = 0; i < min_size; i++)
        r->d[i] = __builtin_subcl(a->d[i], b->d[i], borrow, &borrow);

    if (a->size > min_size)
        for (int i = min_size; i < a->size; i++)
            r->d[i] = __builtin_subcl(a->d[i], 0, borrow, &borrow);

    if (b->size > min_size)
        for (int i = min_size; i < b->size; i++)
            r->d[i] = __builtin_subcl(0, b->d[i], borrow, &borrow);

    for (int i = max_size; i < r->size; i++)
        r->d[i] = __builtin_subcl(0, 0, borrow, &borrow);

    return (uint64_t)borrow;
}

/// @brief Lshifts a into r by k bits
/// @param r Destination (cleared to 0)
/// @param a Source integer
/// @param k Shift count in bits
/// @return Carry shifted past the top, or (uint64_t)-1 on error
uint64_t int_lshift(mprec_int *r, const mprec_int *a, const int k)
{
    if (!r || !a || !r->d || !a->d || k < 0)
        return (uint64_t)-1;

    int big_steps = k / 64;
    int small_steps = k % 64;

    if (r->size < a->size + big_steps)
        return (uint64_t)-1;

    // Reset destination to 0
    memset(r->d, 0, (size_t)r->size * sizeof(uint64_t));

    uint64_t carry = 0;
    for (int i = 0; i < a->size; i++)
    {
        if (small_steps == 0)
        {
            r->d[i + big_steps] = a->d[i];
        }
        else
        {
            uint64_t val = a->d[i];
            r->d[i + big_steps] = (val << small_steps) | carry;
            carry = val >> (64 - small_steps);
        }
    }

    int next_idx = a->size + big_steps;
    if (next_idx < r->size)
    {
        r->d[next_idx] = carry;
        carry = 0;
    }

    return carry;
}

/// @brief Rshifts a into r by k bits
/// @param r Destination (cleared to 0)
/// @param a Source integer
/// @param k Shift count in bits
/// @return Bits dropped from limb 0, or (uint64_t)-1 on error
uint64_t int_rshift(mprec_int *r, const mprec_int *a, const int k)
{
    if (!r || !a || !r->d || !a->d || k < 0)
        return (uint64_t)-1;

    // Reset destination to 0 unconditionally
    memset(r->d, 0, (size_t)r->size * sizeof(uint64_t));

    int big_steps = k / 64;
    int small_steps = k % 64;

    // If shift is greater than or equal to total bit capacity of a, r is 0
    if (big_steps >= a->size)
        return 0;

    if (r->size < a->size - big_steps)
        return (uint64_t)-1;

    uint64_t carry = 0;
    for (int i = a->size - 1; i >= big_steps; i--)
    {
        if (small_steps == 0)
        {
            r->d[i - big_steps] = a->d[i];
        }
        else
        {
            uint64_t val = a->d[i];
            uint64_t next_carry = val << (64 - small_steps);
            r->d[i - big_steps] = (val >> small_steps) | carry;
            carry = next_carry;
        }
    }

    return small_steps > 0 ? (carry >> (64 - small_steps)) : a->d[big_steps];
}

/// @brief Returns true if the bit at position k is 1
bool int_bit_check(const mprec_int *a, const uint64_t k)
{
    if (!a || !a->d || a->size <= 0)
        return false;

    return ((k < (uint64_t)a->size * 64) && ((a->d[k / 64] >> (k % 64)) & 1ULL));
}

/// @brief set the k-th bit to value
void int_bit_set(mprec_int *a, const uint64_t k, bool value)
{
    if (!a || !a->d || k >= (uint64_t)a->size * 64)
        return;

    if (value)
        a->d[k / 64] |= 1ULL << (k % 64);
    else
        a->d[k / 64] &= ~(1ULL << (k % 64));
}

/// @brief Return the position of the first bit => bit length of the number
uint64_t int_bit_length(const mprec_int *a)
{
    if (!a || !a->d)
        return 0;

    for (int i = a->size - 1; i >= 0; i--)
    {
        if (a->d[i] != 0)
        {
            uint64_t lz = __builtin_clzl(a->d[i]);
            return (uint64_t)(64 * (i + 1) - lz);
        }
    }
    return 0;
}
