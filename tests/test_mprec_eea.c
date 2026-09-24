#include "tests.h"

bool eea(mprec_int *g, mprec_int *u, bool *sign_u, mprec_int *v, bool *sign_v, const mprec_int *a, const mprec_int *b);
bool gcd(mprec_int *g, const mprec_int *a, const mprec_int *b);

static bool wrap_eea_full(mprec_int *g, const mprec_int *a, const mprec_int *b)
{
    int max_size = a->size > b->size ? a->size : b->size;
    INTEGER_STACK_ALLOC(u, max_size * 2 * 64);
    INTEGER_STACK_ALLOC(v, max_size * 2 * 64);
    bool sign_u = true, sign_v = true;
    return eea(g, &u, &sign_u, &v, &sign_v, a, b);
}

static void gmp_op_gcd(mpz_t r, const mpz_t a, const mpz_t b) { mpz_gcd(r, a, b); }
static void gmp_op_gcdext(mpz_t r, const mpz_t a, const mpz_t b)
{
    mpz_t s, t;
    mpz_inits(s, t, NULL);
    mpz_gcdext(r, s, t, a, b);
    mpz_clears(s, t, NULL);
}

static const FuncEntry eea_registry[] = {
    {"int_gcd (plain)", OP_BINARY, 200, 500, (void *)gcd, (void *)gmp_op_gcd},
    {"eea (full bezout)", OP_BINARY, 200, 500, (void *)wrap_eea_full, (void *)gmp_op_gcdext},
};
static const int eea_registry_count = sizeof(eea_registry) / sizeof(eea_registry[0]);

int run_mprec_eea_tests(void)
{
    srand(42);
    print_suite_header("MPREC_EEA & GCD ARITHMETIC BENCHMARK", BRIGHT_PURPLE);

    int fails = run_registry_tests(eea_registry, eea_registry_count);
    print_suite_summary(fails);

    if (fails == 0)
    {
        run_registry_benchmarks(eea_registry, eea_registry_count, 256);
        run_registry_benchmarks(eea_registry, eea_registry_count, 512);
    }
    return fails;
}