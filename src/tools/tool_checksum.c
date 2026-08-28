/* tool_checksum.c — Fast Checksum & Hash Suite from FFmpeg */
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

static int checksum_hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int checksum_hex_decode(const char *hex, uint8_t **out, size_t *outlen) {
    if (!hex || !out || !outlen) return -2;
    size_t n = strlen(hex);
    if (n % 2 != 0) return -1;
    uint8_t *buf = malloc(n / 2 + 1);
    if (!buf) return -2;
    for (size_t i = 0; i < n; i += 2) {
        int hi = checksum_hex_nibble((unsigned char)hex[i]);
        int lo = checksum_hex_nibble((unsigned char)hex[i + 1]);
        if (hi < 0 || lo < 0) { free(buf); return -2; }
        buf[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *out = buf;
    *outlen = n / 2;
    return 0;
}

static uint32_t checksum_crc32(const uint8_t *buf, size_t len) {
    if (len == 0) return 0;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)-(int32_t)(crc & 1));
    }
    return crc ^ 0xFFFFFFFFu;
}

static uint32_t checksum_adler32(const uint8_t *buf, size_t len) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + buf[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}

static uint64_t checksum_fnv1a64(const uint8_t *buf, size_t len) {
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < len; i++) {
        h ^= buf[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

static sds tool_checksum_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *algo = cJSON_GetStringValue(cJSON_GetObjectItem(args, "algorithm"));
    if (!algo || !algo[0])
        return sdsnew("ERROR: algorithm required for checksum (crc32, adler32, fnv1a64)");
    if (strcmp(algo, "crc32") != 0 && strcmp(algo, "adler32") != 0 &&
        strcmp(algo, "fnv1a64") != 0 && strcmp(algo, "fnv1a") != 0)
        return sdscatprintf(sdsempty(),
            "ERROR: unknown checksum algorithm %s (use crc32, adler32, or fnv1a64)", algo);

    const char *data_hex = cJSON_GetStringValue(cJSON_GetObjectItem(args, "data"));
    const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
    uint8_t *decoded = NULL;
    size_t len = 0;
    const uint8_t *buf = NULL;
    if (data_hex) {
        int rc = checksum_hex_decode(data_hex, &decoded, &len);
        if (rc == -1)
            return sdsnew("ERROR: hex data length must be an even number of characters");
        if (rc == -2 || !decoded)
            return sdsnew("ERROR: data contains non-hex characters");
        buf = decoded;
    } else if (text) {
        buf = (const uint8_t *)text;
        len = strlen(text);
    } else {
        return sdsnew("ERROR: data (hex) or text input required for checksum");
    }

    sds out;
    if (strcmp(algo, "crc32") == 0) {
        uint32_t v = checksum_crc32(buf, len);
        out = sdscatprintf(sdsempty(),
            "{\"action\":\"checksum\",\"algorithm\":\"crc32\",\"input_bytes\":%zu,"
            "\"value\":%u,\"hex\":\"%08x\"}", len, v, v);
    } else if (strcmp(algo, "adler32") == 0) {
        uint32_t v = checksum_adler32(buf, len);
        out = sdscatprintf(sdsempty(),
            "{\"action\":\"checksum\",\"algorithm\":\"adler32\",\"input_bytes\":%zu,"
            "\"value\":%u,\"hex\":\"%08x\"}", len, v, v);
    } else {
        uint64_t v = checksum_fnv1a64(buf, len);
        out = sdscatprintf(sdsempty(),
            "{\"action\":\"checksum\",\"algorithm\":\"fnv1a64\",\"input_bytes\":%zu,"
            "\"value\":%llu,\"hex\":\"%016llx\"}", len, (unsigned long long)v, (unsigned long long)v);
    }
    if (decoded) free(decoded);
    return out;
}

static const alpha_tool_t tool_checksum = {
    .name = "checksum",
    .aliases = {NULL},
    .category = "crypto",
    .description = "Fast Checksum & Hash Suite from FFmpeg. Computes CRC-32 (IEEE reflected), Adler-32, and FNV-1a 64-bit digests over hex-encoded binary buffers or raw text.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"checksum\",\"description\":\"Fast Checksum & Hash Suite from FFmpeg. Computes CRC-32 (IEEE reflected), Adler-32, and FNV-1a 64-bit digests over hex-encoded binary buffers or raw text.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"algorithm\":{\"type\":\"string\",\"enum\":[\"crc32\",\"adler32\",\"fnv1a64\"],\"description\":\"Digest algorithm\"},\"data\":{\"type\":\"string\",\"description\":\"Hex-encoded binary buffer to digest\"},\"text\":{\"type\":\"string\",\"description\":\"Raw text to digest (used when data is absent)\"}},\"required\":[\"algorithm\"]}}}",
    .run = tool_checksum_run
};
