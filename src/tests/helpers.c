#include "tests.h"

bool gmp_equals_mprec(const mpz_t g, const mprec_int *m)
{
    uint64_t tmp[m->size];
    for (int i = 0; i < m->size; i++)
        tmp[i] = 0;

    size_t count = 0;
    mpz_export(tmp, &count, -1, 8, 0, 0, g);

    for (int i = 0; i < m->size; i++)
    {
        if (m->d[i] != tmp[i])
            return false;
    }
    return true;
}
