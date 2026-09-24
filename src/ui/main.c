#include "colors.h"
#include "tests.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

typedef struct
{
    const char *label;
    void (*action)(void);
} MenuItem;

typedef struct
{
    const char *title;
    const char *subtitle;
    const char *border_color;
    const MenuItem *items;
    int count;
    bool is_root;
} Menu;

static void wait_for_enter(void)
{
    printf("\n" BRIGHT_YELLOW BOLD "Press [Enter] to continue..." RESET);
    fflush(stdout);
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF)
        ;
}

static int get_input(void)
{
    char input_buf[64];
    if (!fgets(input_buf, sizeof(input_buf), stdin))
        return -1;

    int choice = -1;
    if (sscanf(input_buf, "%d", &choice) != 1)
    {
        printf("\n  " BADGE_FAIL "Invalid input. Please enter a number.\n");
        wait_for_enter();
        return -1;
    }
    return choice;
}

static void draw_menu(const Menu *menu)
{
    printf("\033[H\033[2J");
    printf("%s  ┌────────────────────────────────────────────────────────┐\n" RESET, menu->border_color);
    printf("%s  │" BOLD BRIGHT_WHITE " %-54s " RESET "%s│\n" RESET, menu->border_color, menu->title, menu->border_color);
    if (menu->subtitle)
        printf("%s  │" DIM WHITE " %-54s " RESET "%s│\n" RESET, menu->border_color, menu->subtitle, menu->border_color);
    printf("%s  └────────────────────────────────────────────────────────┘\n\n" RESET, menu->border_color);

    for (int i = 0; i < menu->count; i++)
        printf("   " BOLD BRIGHT_GREEN "%d." RESET " " WHITE "%s\n" RESET, i + 1, menu->items[i].label);

    if (menu->is_root)
        printf("   " BOLD BRIGHT_GREEN "0." RESET " " BRIGHT_RED "Exit\n\n" RESET);
    else
        printf("   " BOLD BRIGHT_GREEN "0." RESET " " BRIGHT_YELLOW "Back to previous menu\n\n" RESET);

    printf(DIM BRIGHT_BLACK "  ──────────────────────────────────────────────────────────\n" RESET);
    printf("  " BOLD CYAN "Selection > " RESET);
    fflush(stdout);
}

static void run_menu(const Menu *menu)
{
    while (true)
    {
        draw_menu(menu);
        int choice = get_input();
        if (choice == -1)
            continue;
        if (choice == 0)
            return;

        if (choice > 0 && choice <= menu->count)
        {
            if (menu->items[choice - 1].action)
            {
                menu->items[choice - 1].action();
            }
            else
            {
                printf("\033[H\033[2J\n  " BADGE_INFO BRIGHT_YELLOW "Module not yet implemented.\n" RESET);
                wait_for_enter();
            }
        }
        else
        {
            printf("\n  " BADGE_FAIL "Unknown option: %d\n", choice);
            wait_for_enter();
        }
    }
}

static void action_run(int (*suite_fn)(void))
{
    printf("\033[H\033[2J");
    suite_fn();
    wait_for_enter();
}

static void action_core(void) { action_run(run_mprec_core_tests); }
static void action_adv(void) { action_run(run_mprec_adv_tests); }
static void action_eea(void) { action_run(run_mprec_eea_tests); }
static void action_rand(void) { action_run(run_random_tests); }

static const MenuItem bench_items[] = {
    {"mprec Core Arithmetic & I/O Validation", action_core},
    {"mprec Division & Modular Exponentiation", action_adv},
    {"mprec Extended Euclidean Algorithm & Inversion", action_eea},
    {"Random Number Generation & Primality (Miller-Rabin)", action_rand},
};

static void menu_benchmarks(void)
{
    const Menu menu = {
        .title = "TESTS & BENCHMARKS",
        .subtitle = "Differential fuzzing & performance micro-benchmarks",
        .border_color = BRIGHT_PURPLE,
        .items = bench_items,
        .count = sizeof(bench_items) / sizeof(bench_items[0]),
        .is_root = false};
    run_menu(&menu);
}

static const MenuItem crypto_items[] = {
    {"Miller-Rabin Primality Test (placeholder)", NULL},
    {"RSA Wiener Attack (placeholder)", NULL},
    {"RSA Common Modulus Attack (placeholder)", NULL},
};

static void menu_crypto(void)
{
    const Menu menu = {
        .title = "CRYPTANALYSIS & ATTACKS",
        .subtitle = "CTF Solvers & Cryptographic Primitives",
        .border_color = BRIGHT_BLUE,
        .items = crypto_items,
        .count = sizeof(crypto_items) / sizeof(crypto_items[0]),
        .is_root = false};
    run_menu(&menu);
}

static const MenuItem root_items[] = {
    {"Tests & Benchmarks", menu_benchmarks},
    {"Cryptanalysis & CTF Attacks", menu_crypto},
    {"Interactive REPL Sandbox (placeholder)", NULL},
};

int main(void)
{
    const Menu root_menu = {
        .title = "MY CRYPTO TOOLSUITE",
        .subtitle = "High-Precision Arithmetic, Cryptanalysis & Attacks",
        .border_color = BRIGHT_CYAN,
        .items = root_items,
        .count = sizeof(root_items) / sizeof(root_items[0]),
        .is_root = true};

    run_menu(&root_menu);
    printf("\033[H\033[2J" BRIGHT_CYAN "Exiting crypto toolsuite.\n" RESET);
    return 0;
}