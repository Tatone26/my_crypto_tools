#include "integers.h"
#include <string.h>

bool eea(mprec_int *g, mprec_int *u, bool *sign_u, mprec_int *v, bool *sign_v, const mprec_int *a, const mprec_int *b)
{
    if (!a || !b || !a->d || !b->d)
        return false;

    int max_size = a->size > b->size ? a->size : b->size;
    int work_size = max_size * 2; // Headroom for q * coeff products

    // Remainders
    INTEGER_STACK_ALLOC(r1_m, max_size * 64);
    INTEGER_STACK_ALLOC(r2_m, max_size * 64);
    INTEGER_STACK_ALLOC(rem_m, max_size * 64);
    INTEGER_STACK_ALLOC(q_m, max_size * 64);

    for (int i = 0; i < max_size; i++)
    {
        r1_m.d[i] = (i < a->size) ? a->d[i] : 0;
        r2_m.d[i] = (i < b->size) ? b->d[i] : 0;
    }

    // Bézout u coefficients: u1 = 1, u2 = 0
    INTEGER_STACK_ALLOC(u1_m, work_size * 64);
    INTEGER_STACK_ALLOC(u2_m, work_size * 64);
    INTEGER_STACK_ALLOC(temp_u_m, work_size * 64);

    memset(u1_m.d, 0, (size_t)u1_m.size * sizeof(uint64_t));
    memset(u2_m.d, 0, (size_t)u2_m.size * sizeof(uint64_t));
    u1_m.d[0] = 1ULL;

    bool sign_u1 = true;
    bool sign_u2 = false;

    // Bézout v coefficients: v1 = 0, v2 = 1
    INTEGER_STACK_ALLOC(v1_m, work_size * 64);
    INTEGER_STACK_ALLOC(v2_m, work_size * 64);
    INTEGER_STACK_ALLOC(temp_v_m, work_size * 64);

    memset(v1_m.d, 0, (size_t)v1_m.size * sizeof(uint64_t));
    memset(v2_m.d, 0, (size_t)v2_m.size * sizeof(uint64_t));
    v2_m.d[0] = 1ULL;

    bool sign_v1 = false;
    bool sign_v2 = true;

    mprec_int *r1 = &r1_m;
    mprec_int *r2 = &r2_m;
    mprec_int *rem = &rem_m;
    mprec_int *q = &q_m;

    mprec_int *u1 = &u1_m;
    mprec_int *u2 = &u2_m;
    mprec_int *temp_u = &temp_u_m;

    mprec_int *v1 = &v1_m;
    mprec_int *v2 = &v2_m;
    mprec_int *temp_v = &temp_v_m;

    while (int_bit_length(r2) > 0)
    {
        int_div(q, rem, r1, r2);

        int_mul_add(temp_u, q, u2, u1);
        bool sign_u3 = !sign_u2;

        int_mul_add(temp_v, q, v2, v1);
        bool sign_v3 = !sign_v2;

        mprec_int *temp = r1;
        r1 = r2;
        r2 = rem;
        rem = temp;

        temp = u1;
        u1 = u2;
        sign_u1 = sign_u2;
        u2 = temp_u;
        sign_u2 = sign_u3;
        temp_u = temp;

        temp = v1;
        v1 = v2;
        sign_v1 = sign_v2;
        v2 = temp_v;
        sign_v2 = sign_v3;
        temp_v = temp;
    }

    // Copy GCD
    if (g && g->d)
    {
        int copy_len = g->size < r1->size ? g->size : r1->size;
        for (int i = 0; i < copy_len; i++)
            g->d[i] = r1->d[i];
        for (int i = copy_len; i < g->size; i++)
            g->d[i] = 0;
    }

    // Copy u and sign_u
    if (u && u->d)
    {
        int copy_len = u->size < u1->size ? u->size : u1->size;
        for (int i = 0; i < copy_len; i++)
            u->d[i] = u1->d[i];
        for (int i = copy_len; i < u->size; i++)
            u->d[i] = 0;
    }
    if (sign_u)
        *sign_u = sign_u1;

    // Copy v and sign_v
    if (v && v->d)
    {
        int copy_len = v->size < v1->size ? v->size : v1->size;
        for (int i = 0; i < copy_len; i++)
            v->d[i] = v1->d[i];
        for (int i = copy_len; i < v->size; i++)
            v->d[i] = 0;
    }
    if (sign_v)
        *sign_v = sign_v1;

    return true;
}
