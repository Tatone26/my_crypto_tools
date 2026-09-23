/**
 * This file contains everything needed to read or print numbers.
 */

#include "integers.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

/// @brief Formats an integer to hexadecimal into a buffer.
/// @return Number of characters written (excluding null terminator), or -1 if buffer is too small.
int sprint_hex(const mprec_int *integer, char *buf, size_t buf_size)
{
    if (!integer || !integer->d || integer->size <= 0 || !buf || buf_size < 4)
        return -1;

    int top = integer->size - 1;
    while (top > 0 && integer->d[top] == 0)
        top--;

    int written = snprintf(buf, buf_size, "0x%lx", (unsigned long)integer->d[top]);
    if (written < 0 || (size_t)written >= buf_size)
        return -1;

    for (int i = top - 1; i >= 0; i--)
    {
        int ret = snprintf(buf + written, buf_size - (size_t)written, "%016lx", (unsigned long)integer->d[i]);
        if (ret < 0 || (size_t)(written + ret) >= buf_size)
            return -1;
        written += ret;
    }

    return written;
}

/// @brief Formats an integer to decimal into a buffer.
/// @return Number of characters written (excluding null terminator), or -1 if buffer is too small.
int sprint_dec(const mprec_int *integer, char *buf, size_t buf_size)
{
    if (!integer || !integer->d || integer->size <= 0 || !buf || buf_size < 2)
        return -1;

    int top = integer->size - 1;
    while (top > 0 && integer->d[top] == 0)
        top--;

    if (top == 0 && integer->d[0] == 0)
    {
        buf[0] = '0';
        buf[1] = '\0';
        return 1;
    }

    uint64_t copy[top + 1];
    for (int i = 0; i <= top; i++)
        copy[i] = integer->d[i];

    char dec_digits[(top + 1) * 21 + 1];
    int dec_len = 0;

    while (top >= 0)
    {
        unsigned __int128 rem = 0;
        for (int i = top; i >= 0; i--)
        {
            unsigned __int128 cur = (rem << 64) | copy[i];
            copy[i] = (uint64_t)(cur / 10);
            rem = cur % 10;
        }

        dec_digits[dec_len++] = (char)('0' + (int)rem);

        while (top >= 0 && copy[top] == 0)
            top--;
    }

    if ((size_t)dec_len >= buf_size)
        return -1;

    for (int i = 0; i < dec_len; i++)
        buf[i] = dec_digits[dec_len - 1 - i];

    buf[dec_len] = '\0';
    return dec_len;
}

/// @brief Prints the integer as hex value
void print_hex(const mprec_int *integer, FILE *output)
{
    if (!output || !integer || !integer->d || integer->size <= 0)
        return;
    char buf[integer->size * 16 + 8];
    if (sprint_hex(integer, buf, sizeof(buf)) >= 0)
        fputs(buf, output);
}

/// @brief Prints the integer as decimal value
void print_dec(const mprec_int *integer, FILE *output)
{
    if (!output || !integer || !integer->d || integer->size <= 0)
        return;
    char buf[integer->size * 21 + 8];
    if (sprint_dec(integer, buf, sizeof(buf)) >= 0)
        fputs(buf, output);
}

/// @brief Loads a multi-prec integer from its hexadecimal representation.
/// Explicitly clears the entire buffer `mem->d` to 0.
bool integer_from_hex(mprec_int *mem, const char *hex)
{
    if (!mem || mem->size <= 0 || !mem->d || !hex)
        return false;

    // Full zero-initialization of the destination space
    memset(mem->d, 0, (size_t)mem->size * sizeof(uint64_t));

    int hex_size = (int)strlen(hex);
    if (hex_size == 0)
        return false;

    int idx = 0;
    if (strncmp(hex, "0x", 2) == 0 || strncmp(hex, "0X", 2) == 0)
    {
        idx += 2;
        if (hex_size <= 2)
            return false;
    }

    int curr_block = 0;
    int curr_mult_inside_block = 0;

    for (int i = hex_size - 1; i >= idx; i--)
    {
        if (curr_block >= mem->size)
        {
            // Capacity exceeded: clean up and fail
            memset(mem->d, 0, (size_t)mem->size * sizeof(uint64_t));
            return false;
        }

        uint64_t val = 0;
        if ('0' <= hex[i] && hex[i] <= '9')
            val = (uint64_t)(hex[i] - '0');
        else if ('a' <= hex[i] && hex[i] <= 'f')
            val = (uint64_t)(hex[i] - 'a' + 10);
        else if ('A' <= hex[i] && hex[i] <= 'F')
            val = (uint64_t)(hex[i] - 'A' + 10);
        else
        {
            // Invalid character: clean up and fail
            memset(mem->d, 0, (size_t)mem->size * sizeof(uint64_t));
            return false;
        }

        mem->d[curr_block] |= (val << curr_mult_inside_block);

        curr_mult_inside_block += 4;
        if (curr_mult_inside_block >= 64)
        {
            curr_mult_inside_block = 0;
            curr_block++;
        }
    }

    return true;
}

/// @brief Loads a multi-prec integer from its decimal representation.
/// Explicitly clears the entire buffer `mem->d` to 0.
bool integer_from_dec(mprec_int *mem, const char *dec)
{
    if (!mem || mem->size <= 0 || !mem->d || !dec)
        return false;

    // Full zero-initialization of the destination space
    memset(mem->d, 0, (size_t)mem->size * sizeof(uint64_t));

    int dec_size = (int)strlen(dec);
    if (dec_size == 0)
        return false;

    int idx = 0;
    if (strncmp(dec, "0d", 2) == 0 || strncmp(dec, "0D", 2) == 0)
    {
        idx += 2;
        if (dec_size <= 2)
            return false;
    }

    for (int i = idx; i < dec_size; i++)
    {
        if (dec[i] < '0' || dec[i] > '9')
        {
            // Invalid character: clean up and fail
            memset(mem->d, 0, (size_t)mem->size * sizeof(uint64_t));
            return false;
        }

        int digit = dec[i] - '0';
        unsigned __int128 carry = digit;

        for (int s = 0; s < mem->size; s++)
        {
            unsigned __int128 prod = (unsigned __int128)mem->d[s] * 10 + carry;
            mem->d[s] = (uint64_t)(prod & 0xFFFFFFFFFFFFFFFFULL);
            carry = prod >> 64;
        }

        if (carry > 0)
        {
            // Overflow past capacity: clean up and fail
            memset(mem->d, 0, (size_t)mem->size * sizeof(uint64_t));
            return false;
        }
    }

    return true;
}