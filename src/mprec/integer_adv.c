#include "integers.h"
#include <stdlib.h>

/// @brief Computes (a * b) + c without 128-bit types
void mul_add64(uint64_t *hi, uint64_t *lo, const uint64_t a, const uint64_t b, const uint64_t c)
{
    uint64_t a_lo = a & 0xFFFFFFFFULL;
    uint64_t a_hi = a >> 32;
    uint64_t b_lo = b & 0xFFFFFFFFULL;
    uint64_t b_hi = b >> 32;

    uint64_t p0 = a_lo * b_lo;
    uint64_t p1 = a_lo * b_hi;
    uint64_t p2 = a_hi * b_lo;
    uint64_t p3 = a_hi * b_hi;

    unsigned long carry_mid = 0;
    uint64_t mid = p1 + p2;
    if (mid < p1)
        carry_mid = 1;

    uint64_t mid_lo = mid << 32;
    uint64_t mid_hi = (mid >> 32) | ((uint64_t)carry_mid << 32);

    unsigned long c1 = 0;
    unsigned long c2 = 0;
    uint64_t res_lo = __builtin_addcl(p0, mid_lo, 0, &c1);
    res_lo = __builtin_addcl(res_lo, c, 0, &c2);

    *lo = res_lo;
    *hi = p3 + mid_hi + c1 + c2;
}

/// @brief Computes r = (a * b) + c for multi-precision integers
/// @param r Destination (cleared to 0)
/// @param a Operand 1
/// @param b Operand 2
/// @param c Operand 3 (addend)
/// @return Overflow past r->size, or (uint64_t)-1 on error
uint64_t int_mul_add(mprec_int *r, const mprec_int *a, const mprec_int *b, const mprec_int *c)
{
    if (!r || !a || !b || !r->d || !a->d || !b->d)
        return (uint64_t)-1;

    int min_required = a->size + b->size;
    if (c && c->size > min_required)
        min_required = c->size;
    if (r->size < min_required)
        return (uint64_t)-1;

    // Reset destination to 0
    memset(r->d, 0, (size_t)r->size * sizeof(uint64_t));

    // Initialize r with c
    if (c)
        for (int i = 0; i < c->size; i++)
            r->d[i] = c->d[i];

    // Schoolbook multiplication accumulating directly into r
    for (int i = 0; i < a->size; i++)
    {
        if (a->d[i] == 0)
            continue;

        uint64_t carry = 0;
        for (int j = 0; j < b->size; j++)
        {
            uint64_t hi = 0;
            uint64_t lo = 0;
            mul_add64(&hi, &lo, a->d[i], b->d[j], carry);

            unsigned long add_c = 0;
            r->d[i + j] = __builtin_addcl(r->d[i + j], lo, 0, &add_c);
            carry = hi + add_c;
        }

        int k = i + b->size;
        while (carry > 0 && k < r->size)
        {
            unsigned long add_c = 0;
            r->d[k] = __builtin_addcl(r->d[k], carry, 0, &add_c);
            carry = add_c;
            k++;
        }

        if (carry > 0)
            return carry;
    }

    return 0;
}

/// @brief Slow, bit-by-bit implementation of division with remainder. See https://en.wikipedia.org/wiki/Division_algorithm#Integer_division_(unsigned)_with_remainder for my base.
/// If q is null, it acts as a remainder operations (modulo).
///
/// Painfully slow anyway. Got switching of buffers and all. Really bad. Will do better later. BUT, it works!
/// @param q pre-allocated quotient
/// @param r pre-allocated remainder
/// @param a int 1
/// @param b int 2
/// @return false if any error happened
bool int_div(mprec_int *q, mprec_int *r, const mprec_int *a, const mprec_int *b)
{
    if (!a || !b || !r || int_bit_length(b) == 0)
        return false;

    if (q && q->d)
        for (int i = 0; i < q->size; i++)
            q->d[i] = 0;

    for (int i = 0; i < r->size; i++)
        r->d[i] = 0;

    INTEGER_STACK_ALLOC(temp_r, r->size * 64);

    uint64_t a_bits = int_bit_length(a);
    if (a_bits == 0)
        return true; // 0 / b = 0, r already set to 0

    for (int k = (int)a_bits - 1; k >= 0; k--)
    {
        int_lshift(&temp_r, r, 1);
        int_bit_set(&temp_r, 0, int_bit_check(a, k));

        if (int_cmp(&temp_r, b) >= 0)
        {
            int_sub(r, &temp_r, b);
            if (q)
                int_bit_set(q, k, 1);
        }
        else
            for (int i = 0; i < r->size; i++)
                r->d[i] = temp_r.d[i];
    }

    return true;
}

bool int_exp_mod(mprec_int *r, const mprec_int *a, const mprec_int *k, const mprec_int *N)
{
    if (!a || !r || !k || !N || int_bit_length(N) == 0)
        return false;

    // Edge case: N == 1 => anything mod 1 is 0
    if (int_bit_length(N) == 1 && int_bit_check(N, 0))
    {
        for (int i = 0; i < r->size; i++)
            r->d[i] = 0;
        return true;
    }

    INTEGER_STACK_ALLOC(res_m, N->size * 64);
    for (int i = 0; i < res_m.size; i++)
        res_m.d[i] = 0;
    res_m.d[0] = 1ULL;

    INTEGER_STACK_ALLOC(temp_m, N->size * 2 * 64);

    INTEGER_STACK_ALLOC(a_mod, N->size * 64);
    int_mod(&a_mod, a, N);

    mprec_int *res = &res_m;
    mprec_int *temp = &temp_m;

    int total_bits = (int)int_bit_length(k);
    for (int i = total_bits - 1; i >= 0; i--)
    {
        // res = (res * res) % N
        int_mul_add(temp, res, res, NULL);
        int_mod(res, temp, N);

        if (int_bit_check(k, i))
        {
            // res = (res * a_mod) % N
            int_mul_add(temp, res, &a_mod, NULL);
            int_mod(res, temp, N);
        }
    }

    int copy_limbs = r->size < res->size ? r->size : res->size;
    for (int i = 0; i < copy_limbs; i++)
        r->d[i] = res->d[i];
    for (int i = copy_limbs; i < r->size; i++)
        r->d[i] = 0;

    return true;
}