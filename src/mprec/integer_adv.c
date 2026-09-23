#include "integers.h"
#include <stdlib.h>

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