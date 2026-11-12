//
//  sfs_encoding.c
//  securefs
//

#include "sfs_encoding.h"

#include <string.h>

static const char kBase32Upper[] = "ABCDEFGHIJKMNPQRSTUVWXYZ23456789";

static int base32_value(char c)
{
    if (c >= 'a' && c <= 'z') {
        c = (char)(c - 'a' + 'A');
    }
    const char *found = c ? strchr(kBase32Upper, c) : NULL;
    return found ? (int)(found - kBase32Upper) : -1;
}

void sfs_base32_encode(const uint8_t *in, size_t len, char *out)
{
    // Standard most-significant-bit-first base32 grouping with the securefs alphabet.
    size_t o = 0;
    for (size_t bit = 0; bit < len * 8; bit += 5) {
        size_t byte_index = bit / 8, shift = bit % 8;
        unsigned value = (unsigned)in[byte_index] << 8;
        if (byte_index + 1 < len) {
            value |= in[byte_index + 1];
        }
        out[o++] = kBase32Upper[(value >> (11 - shift)) & 31u];
    }
    out[o] = '\0';
}

bool sfs_base32_decode(const char *in, size_t len, uint8_t *out, size_t *out_len)
{
    size_t n = sfs_base32_decoded_len(len);
    memset(out, 0, n);
    for (size_t i = 0; i < len; ++i) {
        int v = base32_value(in[i]);
        if (v < 0) {
            return false;
        }
        size_t bit = i * 5, byte_index = bit / 8, shift = bit % 8;
        // Place the 5-bit group starting `shift` bits into byte_index; bits beyond the
        // decoded length are discarded (they are the zero padding of the final group).
        unsigned spread = (unsigned)v << (11 - shift);
        if (byte_index < n) {
            out[byte_index] |= (uint8_t)(spread >> 8);
        }
        if (byte_index + 1 < n) {
            out[byte_index + 1] |= (uint8_t)(spread & 0xff);
        }
    }
    *out_len = n;
    return true;
}

static const char kBase64Url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void sfs_base64url_encode(const uint8_t *in, size_t len, char *out)
{
    size_t o = 0, i = 0;
    for (; i + 3 <= len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = kBase64Url[(v >> 18) & 63];
        out[o++] = kBase64Url[(v >> 12) & 63];
        out[o++] = kBase64Url[(v >> 6) & 63];
        out[o++] = kBase64Url[v & 63];
    }
    if (len - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = kBase64Url[(v >> 18) & 63];
        out[o++] = kBase64Url[(v >> 12) & 63];
    } else if (len - i == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = kBase64Url[(v >> 18) & 63];
        out[o++] = kBase64Url[(v >> 12) & 63];
        out[o++] = kBase64Url[(v >> 6) & 63];
    }
    out[o] = '\0';
}

static int base64url_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

bool sfs_base64url_decode(const char *in, size_t len, uint8_t *out, size_t *out_len)
{
    while (len > 0 && in[len - 1] == '=') {
        --len;
    }
    if (len % 4 == 1) {
        return false;
    }
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < len; ++i) {
        int v = base64url_value(in[i]);
        if (v < 0) {
            return false;
        }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)((acc >> bits) & 0xff);
        }
    }
    *out_len = o;
    return true;
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool sfs_hex_decode(const char *in, size_t len, uint8_t *out, size_t out_len)
{
    if (len % 2 != 0 || len / 2 != out_len) {
        return false;
    }
    for (size_t i = 0; i < out_len; ++i) {
        int hi = hex_value(in[2 * i]), lo = hex_value(in[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}
