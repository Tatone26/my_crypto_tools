#include "tests.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

static int test_random_invariants(int iterations)
{
    printf(BADGE_RUN CYAN "%-18s (%d runs)... " RESET, "Bit-length & Parity", iterations);
    fflush(stdout);

    INTEGER_STACK_ALLOC(r, 1024);
    int fails = 0;

    for (int i = 0; i < iterations; i++)
    {
        int target_bits = 2 + (rand() % 1022); // 2 to 1024 bits

        // 1. Check exact bit length on random_number
        random_number(&r, target_bits);
        uint64_t actual_bits = int_bit_length(&r);

        if (actual_bits != (uint64_t)target_bits)
        {
            printf("\n" BADGE_FAIL "random_number: requested %d bits, got %lu!\n", target_bits, (unsigned long)actual_bits);
            fails++;
            break;
        }

        // 2. Check oddness and bit length on random_odd_number
        random_odd_number(&r, target_bits);
        actual_bits = int_bit_length(&r);

        if (actual_bits != (uint64_t)target_bits)
        {
            printf("\n" BADGE_FAIL "random_odd_number: requested %d bits, got %lu!\n", target_bits, (unsigned long)actual_bits);
            fails++;
            break;
        }

        if (!int_bit_check(&r, 0))
        {
            printf("\n" BADGE_FAIL "random_odd_number: LSB was 0 (even)!\n");
            fails++;
            break;
        }
    }

    if (fails == 0)
        printf(BADGE_PASS "\n");
    return fails;
}

static int test_random_statistics(int total_samples)
{
    printf(BADGE_RUN CYAN "%-18s (%d 512-bit samples)... " RESET, "Entropy / Chi-Square", total_samples);
    fflush(stdout);

    INTEGER_STACK_ALLOC(r, 512);

    uint64_t total_bits = 0;
    uint64_t set_bits = 0;
    uint64_t byte_counts[256] = {0};

    for (int i = 0; i < total_samples; i++)
    {
        random_number(&r, 512);

        // Exclude the top MSB limb bit from Hamming weight to avoid bias from the forced '1'
        for (int b = 0; b < 511; b++)
        {
            total_bits++;
            if (int_bit_check(&r, b))
                set_bits++;
        }

        // Count byte frequencies for middle limbs
        uint8_t *bytes = (uint8_t *)r.d;
        for (size_t j = 0; j < (512 / 8) - 1; j++)
            byte_counts[bytes[j]]++;
    }

    // 1. Bit-ratio check (Hamming weight should be within 49% - 51%)
    double bit_ratio = (double)set_bits / (double)total_bits;
    if (bit_ratio < 0.485 || bit_ratio > 0.515)
    {
        printf("\n" BADGE_FAIL "Extreme bit imbalance: %.4f (expected ~0.500)\n", bit_ratio);
        return 1;
    }

    // 2. Chi-Square goodness-of-fit for uniform byte distribution
    double total_bytes = (double)(total_samples * ((512 / 8) - 1));
    double expected_per_bucket = total_bytes / 256.0;
    double chi_square = 0.0;

    for (int i = 0; i < 256; i++)
    {
        double diff = (double)byte_counts[i] - expected_per_bucket;
        chi_square += (diff * diff) / expected_per_bucket;
    }

    // For df = 255, critical value at alpha=0.001 is ~310
    if (chi_square > 320.0)
    {
        printf("\n" BADGE_FAIL "Chi-square distribution test failed: %.2f > 320\n", chi_square);
        return 1;
    }

    printf(BADGE_PASS WHITE "(Bit Ratio: " BOLD GREEN "%.3f" RESET WHITE ", Chi²: " BOLD GREEN "%.1f" RESET WHITE ")\n" RESET,
           bit_ratio, chi_square);
    return 0;
}

int run_random_tests(void)
{
    printf("\n" BRIGHT_CYAN "┌────────────────────────────────────────────────────────┐\n" RESET);
    printf(BRIGHT_CYAN "│" BOLD BRIGHT_WHITE "           CSPRNG / RANDOMNESS VALIDATION               " RESET BRIGHT_CYAN "│\n" RESET);
    printf(BRIGHT_CYAN "└────────────────────────────────────────────────────────┘\n\n" RESET);

    int fails = 0;
    fails += test_random_invariants(5000);
    fails += test_random_statistics(2000);

    if (fails == 0)
        printf("\n" BADGE_PASS BOLD GREEN "All randomness checks passed successfully!" RESET "\n");
    else
        printf("\n" BADGE_FAIL BOLD RED "Randomness checks detected failures." RESET "\n");

    return fails;
}