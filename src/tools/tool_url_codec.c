/* tool_url_codec.c — RFC 3986 URL & Query String Parser, Percent Codec, and Levenshtein Distance Matrix from php/php-src */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static sds tool_url_codec_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "parse";

    if (strcmp(action, "encode") == 0) {
        const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
        if (!text) return sdsnew("ERROR: text parameter required for encode");
        sds enc = sdsempty();
        static const char hexchars[] = "0123456789ABCDEF";
        for (size_t i = 0; text[i]; i++) {
            unsigned char c = (unsigned char)text[i];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
                enc = sdscatlen(enc, &text[i], 1);
            } else {
                enc = sdscatprintf(enc, "%%%c%c", hexchars[c >> 4], hexchars[c & 0x0F]);
            }
        }
        sds out = sdscatprintf(sdsempty(), "{\"action\":\"encode\",\"input\":\"%s\",\"encoded\":\"%s\"}", text, enc);
        sdsfree(enc);
        return out;
    }

    if (strcmp(action, "decode") == 0) {
        const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
        if (!text) return sdsnew("ERROR: text parameter required for decode");
        sds dec = sdsempty();
        for (size_t i = 0; text[i]; i++) {
            if (text[i] == '+' && !cJSON_IsTrue(cJSON_GetObjectItem(args, "preserve_plus"))) {
                dec = sdscatlen(dec, " ", 1);
            } else if (text[i] == '%' && text[i+1] && text[i+2]) {
                char h[3] = { text[i+1], text[i+2], 0 };
                char *endp = NULL;
                long v = strtol(h, &endp, 16);
                if (endp && *endp == 0 && v >= 0 && v <= 255) {
                    char ch = (char)v;
                    dec = sdscatlen(dec, &ch, 1);
                    i += 2;
                } else {
                    dec = sdscatlen(dec, &text[i], 1);
                }
            } else {
                dec = sdscatlen(dec, &text[i], 1);
            }
        }
        sds out = sdscatprintf(sdsempty(), "{\"action\":\"decode\",\"decoded\":\"%s\"}", dec);
        sdsfree(dec);
        return out;
    }

    if (strcmp(action, "parse") == 0) {
        const char *url_str = cJSON_GetStringValue(cJSON_GetObjectItem(args, "url"));
        if (!url_str) return sdsnew("ERROR: url parameter required for parse");

        const char *p = url_str;
        sds scheme = sdsempty(), user = sdsempty(), pass = sdsempty();
        sds host = sdsempty(), path = sdsempty(), query = sdsempty(), fragment = sdsempty();
        int port = 0;

        const char *scheme_end = strstr(p, "://");
        if (scheme_end) {
            scheme = sdscatlen(scheme, p, (size_t)(scheme_end - p));
            p = scheme_end + 3;
        }

        const char *frag_start = strchr(p, '#');
        if (frag_start) {
            fragment = sdscat(fragment, frag_start + 1);
        }

        size_t main_len = frag_start ? (size_t)(frag_start - p) : strlen(p);
        sds main_part = sdsnewlen(p, main_len);

        const char *q_start = strchr(main_part, '?');
        if (q_start) {
            query = sdscat(query, q_start + 1);
        }

        size_t auth_host_len = q_start ? (size_t)(q_start - main_part) : sdslen(main_part);
        sds auth_host = sdsnewlen(main_part, auth_host_len);

        const char *path_start = strchr(auth_host, '/');
        if (path_start) {
            path = sdscat(path, path_start);
        } else {
            path = sdsnew("/");
        }

        size_t host_part_len = path_start ? (size_t)(path_start - auth_host) : sdslen(auth_host);
        sds host_part = sdsnewlen(auth_host, host_part_len);

        const char *at_sign = strchr(host_part, '@');
        const char *host_str = host_part;
        if (at_sign) {
            size_t userinfo_len = (size_t)(at_sign - host_part);
            const char *colon = memchr(host_part, ':', userinfo_len);
            if (colon) {
                user = sdscatlen(user, host_part, (size_t)(colon - host_part));
                pass = sdscatlen(pass, colon + 1, (size_t)(at_sign - (colon + 1)));
            } else {
                user = sdscatlen(user, host_part, userinfo_len);
            }
            host_str = at_sign + 1;
        }

        const char *port_colon = strrchr(host_str, ':');
        if (port_colon && *(port_colon + 1) >= '0' && *(port_colon + 1) <= '9') {
            host = sdscatlen(host, host_str, (size_t)(port_colon - host_str));
            port = atoi(port_colon + 1);
        } else {
            host = sdscat(host, host_str);
        }

        cJSON *params_obj = cJSON_CreateObject();
        if (sdslen(query) > 0) {
            char *qcopy = strdup(query);
            char *tok = strtok(qcopy, "&");
            while (tok) {
                char *eq = strchr(tok, '=');
                if (eq) {
                    *eq = 0;
                    char *k = tok;
                    char *v = eq + 1;
                    sds v_dec = sdsempty();
                    for (size_t vi = 0; v[vi]; vi++) {
                        if (v[vi] == '+') v_dec = sdscatlen(v_dec, " ", 1);
                        else if (v[vi] == '%' && v[vi+1] && v[vi+2]) {
                            char h[3] = { v[vi+1], v[vi+2], 0 };
                            char *ep = NULL; long val = strtol(h, &ep, 16);
                            if (ep && *ep == 0 && val >= 0 && val <= 255) {
                                char c = (char)val; v_dec = sdscatlen(v_dec, &c, 1); vi += 2;
                            } else v_dec = sdscatlen(v_dec, &v[vi], 1);
                        } else v_dec = sdscatlen(v_dec, &v[vi], 1);
                    }
                    cJSON_AddStringToObject(params_obj, k, v_dec);
                    sdsfree(v_dec);
                } else {
                    cJSON_AddStringToObject(params_obj, tok, "");
                }
                tok = strtok(NULL, "&");
            }
            free(qcopy);
        }

        char *params_json = cJSON_PrintUnformatted(params_obj);
        cJSON_Delete(params_obj);

        sds out = sdscatprintf(sdsempty(),
            "{\"action\":\"parse\",\"scheme\":\"%s\",\"user\":\"%s\",\"pass\":\"%s\","
            "\"host\":\"%s\",\"port\":%d,\"path\":\"%s\",\"query\":\"%s\",\"fragment\":\"%s\",\"params\":%s}",
            scheme, user, pass, host, port, path, query, fragment, params_json ? params_json : "{}");

        if (params_json) free(params_json);
        sdsfree(scheme); sdsfree(user); sdsfree(pass);
        sdsfree(host); sdsfree(path); sdsfree(query); sdsfree(fragment);
        sdsfree(main_part); sdsfree(auth_host); sdsfree(host_part);
        return out;
    }

    if (strcmp(action, "build") == 0) {
        const char *scheme = cJSON_GetStringValue(cJSON_GetObjectItem(args, "scheme"));
        const char *host = cJSON_GetStringValue(cJSON_GetObjectItem(args, "host"));
        if (!host) return sdsnew("ERROR: host parameter required for build");
        int port = 0;
        cJSON *p_item = cJSON_GetObjectItem(args, "port");
        if (cJSON_IsNumber(p_item)) port = (int)p_item->valuedouble;
        const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
        const char *query = cJSON_GetStringValue(cJSON_GetObjectItem(args, "query"));
        const char *fragment = cJSON_GetStringValue(cJSON_GetObjectItem(args, "fragment"));

        sds url = sdsempty();
        if (scheme && scheme[0]) url = sdscatprintf(url, "%s://", scheme);
        url = sdscat(url, host);
        if (port > 0 && port != 80 && port != 443) url = sdscatprintf(url, ":%d", port);
        if (path && path[0]) {
            if (path[0] != '/') url = sdscat(url, "/");
            url = sdscat(url, path);
        }
        if (query && query[0]) url = sdscatprintf(url, "?%s", query);
        if (fragment && fragment[0]) url = sdscatprintf(url, "#%s", fragment);

        sds out = sdscatprintf(sdsempty(), "{\"action\":\"build\",\"url\":\"%s\"}", url);
        sdsfree(url);
        return out;
    }

    if (strcmp(action, "levenshtein") == 0 || strcmp(action, "distance") == 0) {
        const char *s1 = cJSON_GetStringValue(cJSON_GetObjectItem(args, "a"));
        const char *s2 = cJSON_GetStringValue(cJSON_GetObjectItem(args, "b"));
        if (!s1 || !s2) return sdsnew("ERROR: 'a' and 'b' string parameters required for levenshtein");

        int cost_ins = 1, cost_rep = 1, cost_del = 1;
        cJSON *ci = cJSON_GetObjectItem(args, "cost_ins");
        if (cJSON_IsNumber(ci) && ci->valuedouble >= 0) cost_ins = (int)ci->valuedouble;
        cJSON *cr = cJSON_GetObjectItem(args, "cost_rep");
        if (cJSON_IsNumber(cr) && cr->valuedouble >= 0) cost_rep = (int)cr->valuedouble;
        cJSON *cd = cJSON_GetObjectItem(args, "cost_del");
        if (cJSON_IsNumber(cd) && cd->valuedouble >= 0) cost_del = (int)cd->valuedouble;

        size_t l1 = strlen(s1), l2 = strlen(s2);
        long *p1 = malloc((l2 + 1) * sizeof(long));
        long *p2 = malloc((l2 + 1) * sizeof(long));
        if (!p1 || !p2) { if (p1) free(p1); if (p2) free(p2); return sdsnew("ERROR: allocation failed"); }

        for (size_t i2 = 0; i2 <= l2; i2++) p1[i2] = (long)i2 * cost_ins;
        for (size_t i1 = 0; i1 < l1; i1++) {
            p2[0] = p1[0] + cost_del;
            for (size_t i2 = 0; i2 < l2; i2++) {
                long c0 = p1[i2] + ((s1[i1] == s2[i2]) ? 0 : cost_rep);
                long c1 = p1[i2 + 1] + cost_del;
                if (c1 < c0) c0 = c1;
                long c2 = p2[i2] + cost_ins;
                if (c2 < c0) c0 = c2;
                p2[i2 + 1] = c0;
            }
            long *tmp = p1; p1 = p2; p2 = tmp;
        }
        long dist = p1[l2];
        free(p1); free(p2);

        size_t max_len = l1 > l2 ? l1 : l2;
        int max_cost = cost_rep > cost_ins ? cost_rep : cost_ins;
        if (cost_del > max_cost) max_cost = cost_del;
        double similarity = (max_len == 0) ? 1.0 : (1.0 - ((double)dist / (double)(max_len * max_cost)));
        if (similarity < 0.0) similarity = 0.0;

        return sdscatprintf(sdsempty(),
            "{\"action\":\"levenshtein\",\"distance\":%ld,\"similarity\":%.4f,\"len_a\":%zu,\"len_b\":%zu,\"cost_ins\":%d,\"cost_rep\":%d,\"cost_del\":%d}",
            dist, similarity, l1, l2, cost_ins, cost_rep, cost_del);
    }

    return sdscatprintf(sdsempty(), "ERROR: unknown url_codec_parser action '%s'", action);
}

static const alpha_tool_t tool_url_codec = {
    .name = "url_codec_parser",
    .aliases = {"url_codec", NULL},
    .category = "codec",
    .description = "RFC 3986 URL & Query String Parser, Percent Codec, and Levenshtein Distance Matrix from php/php-src. Actions: 'parse' (extracts scheme/user/pass/host/port/path/query/fragment/params), 'build' (constructs canonical URL), 'encode'/'decode' (percent codec), 'levenshtein' (weighted edit distance & similarity).",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"url_codec_parser\",\"description\":\"RFC 3986 URL & Query String Parser, Percent Codec, and Levenshtein Distance Matrix from php/php-src. Actions: 'parse' (extracts scheme/user/pass/host/port/path/query/fragment/params), 'build' (constructs canonical URL), 'encode'/'decode' (percent codec), 'levenshtein' (weighted edit distance & similarity).\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"parse\",\"build\",\"encode\",\"decode\",\"levenshtein\"]},\"url\":{\"type\":\"string\",\"description\":\"URL string to parse\"},\"text\":{\"type\":\"string\",\"description\":\"Text to encode or decode\"},\"scheme\":{\"type\":\"string\"},\"host\":{\"type\":\"string\"},\"port\":{\"type\":\"integer\"},\"path\":{\"type\":\"string\"},\"query\":{\"type\":\"string\"},\"fragment\":{\"type\":\"string\"},\"a\":{\"type\":\"string\",\"description\":\"First string for levenshtein\"},\"b\":{\"type\":\"string\",\"description\":\"Second string for levenshtein\"},\"cost_ins\":{\"type\":\"integer\"},\"cost_rep\":{\"type\":\"integer\"},\"cost_del\":{\"type\":\"integer\"}},\"required\":[]}}}",
    .run = tool_url_codec_run
};
