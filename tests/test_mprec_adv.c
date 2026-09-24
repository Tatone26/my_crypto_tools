#include "tests.h"

bool int_div(mprec_int *q, mprec_int *r, const mprec_int *a, const mprec_int *b);
bool int_exp_mod(mprec_int *r, const mprec_int *a, const mprec_int *k, const mprec_int *N);

static void gmp_op_div(mpz_t r, const mpz_t a, const mpz_t b) { mpz_tdiv_q(r, a, b); }
static void gmp_op_rem(mpz_t r, const mpz_t a, const mpz_t b) { mpz_tdiv_r(r, a, b); }
static void gmp_op_exp_mod(mpz_t r, const mpz_t a, const mpz_t k, const mpz_t n) { mpz_powm(r, a, k, n); }

static bool wrap_int_div(mprec_int *q, const mprec_int *a, const mprec_int *b)
{
    INTEGER_STACK_ALLOC(rem, 2048);
    return int_div(q, &rem, a, b);
}

static bool wrap_int_rem(mprec_int *r, const mprec_int *a, const mprec_int *b)
{
    return int_div(NULL, r, a, b);
}

static const FuncEntry adv_registry[] = {
    {"int_div_q", OP_BINARY, 500, 2000, (void *)wrap_int_div, (void *)gmp_op_div},
    {"int_div_r", OP_BINARY, 500, 2000, (void *)wrap_int_rem, (void *)gmp_op_rem},
    {"int_exp_mod", OP_TERNARY, 100, 100, (void *)int_exp_mod, (void *)gmp_op_exp_mod},
};
static const int adv_registry_count = sizeof(adv_registry) / sizeof(adv_registry[0]);

int run_mprec_adv_tests(void)
{
    srand(42);
    print_suite_header("MPREC_ADV MODULAR & DIV BENCHMARK", BRIGHT_PURPLE);

    int fails = run_registry_tests(adv_registry, adv_registry_count);
    print_suite_summary(fails);

    if (fails == 0)
    {
        run_registry_benchmarks(adv_registry, adv_registry_count, 256);
        run_registry_benchmarks(adv_registry, adv_registry_count, 512);
    }
    return fails;
}