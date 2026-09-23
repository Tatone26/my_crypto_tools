#ifndef COLORS_H
#define COLORS_H

// Text attributes & resets
#define RESET "\033[0m"
#define BOLD "\033[1m"
#define DIM "\033[2m"
#define ITALIC "\033[3m"
#define UNDERLINE "\033[4m"
#define INVERT "\033[7m"

// Standard foregrounds
#define BLACK "\033[30m"
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define WHITE "\033[37m"

// High-intensity foregrounds
#define BRIGHT_BLACK "\033[90m"
#define BRIGHT_RED "\033[91m"
#define BRIGHT_GREEN "\033[92m"
#define BRIGHT_YELLOW "\033[93m"
#define BRIGHT_BLUE "\033[94m"
#define BRIGHT_PURPLE "\033[95m"
#define BRIGHT_CYAN "\033[96m"
#define BRIGHT_WHITE "\033[97m"

// Standard backgrounds
#define BG_BLACK "\033[40m"
#define BG_RED "\033[41m"
#define BG_GREEN "\033[42m"
#define BG_YELLOW "\033[43m"
#define BG_BLUE "\033[44m"
#define BG_MAGENTA "\033[45m"
#define BG_CYAN "\033[46m"
#define BG_WHITE "\033[47m"

// Semantic test badges using standard 16-color ANSI
#define BADGE_PASS BOLD BG_GREEN BLACK " PASS " RESET " "
#define BADGE_FAIL BOLD BG_RED WHITE " FAIL " RESET " "
#define BADGE_RUN BOLD BG_CYAN BLACK " FUZZ " RESET " "
#define BADGE_BENCH BOLD BG_YELLOW BLACK " BENCH " RESET " "
#define BADGE_INFO BOLD BG_BLUE WHITE " INFO " RESET " "

#endif // COLORS_H