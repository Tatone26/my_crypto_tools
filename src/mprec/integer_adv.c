#include "integers.h"

bool int_div(mprec_int *q, mprec_int *r, const mprec_int *a, const mprec_int *b)
{
    if (int_bit_length(b) == 0)
        return false;

    for (int i = 0; i < q->size; i++)
        q->d[i] = 0;
    for (int i = 0; i < r->size; i++)
        r->d[i] = 0;

    INTEGER_STACK_ALLOC(temp_r, r->size);
    U64_TO_MPREC(zero, 0);

    for (int k = a->size * 64 - 1; k >= 0; k--)
    {
        int_lshift(&temp_r, r, 1);
        temp_r.d[0] |= (int_bit_check(a, k) ? 1UL : 0UL);
        if (int_cmp(&temp_r, b) >= 0)
        {
            int_sub(r, &temp_r, b);
            int_bit_set(q, k, 1);
        }
        else
            int_add(r, &temp_r, &zero); // set r to temp_r
    }

    return true;
}