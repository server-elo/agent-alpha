#include "../include/web.h"

#include <ctype.h>
#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#ifndef WEB_UA
/* Browser-like UA (Elo/OpenClaw web_fetch style) — keyless direct fetch, no Brave on fetch */
#define WEB_UA "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
#endif

typedef struct {
    sds body;
} buf_t;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    buf_t *b = (buf_t *)userdata;
    size_t n = size * nmemb;
    b->body = sdscatlen(b->body, ptr, n);
    return n;
}

static const char *env_or(const char *k, const char *def) {
    const char *v = getenv(k);
    return (v && v[0]) ? v : def;
}

sds http_get(const char *url, const char *extra_header, long timeout_s, long *http_code_out) {
    if (!url || !url[0]) return sdsnew("ERROR: empty url");
    CURL *curl = curl_easy_init();
    if (!curl) return sdsnew("ERROR: curl init failed");

    buf_t st = {.body = sdsempty()};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "User-Agent: " WEB_UA);
    headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.8");
    if (extra_header && extra_header[0]) headers = curl_slist_append(headers, extra_header);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &st);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    /* Search engines often hang; keep connect short. Full page fetches still get full timeout. */
    long cto = (timeout_s > 0 && timeout_s <= 15) ? 4L : 8L;
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, cto);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_s > 0 ? timeout_s : 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (http_code_out) *http_code_out = code;

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        sds err = sdscatprintf(sdsempty(), "ERROR: curl %s", curl_easy_strerror(res));
        sdsfree(st.body);
        return err;
    }
    if (code >= 400) {
        sds err = sdscatprintf(sdsempty(), "ERROR: HTTP %ld for %s\n%.400s", code, url, st.body);
        sdsfree(st.body);
        return err;
    }
    return st.body;
}

sds http_post(const char *url, const char *post_fields, const char *extra_header, long timeout_s, long *http_code_out) {
    if (!url || !url[0]) return sdsnew("ERROR: empty url");
    CURL *curl = curl_easy_init();
    if (!curl) return sdsnew("ERROR: curl init failed");

    buf_t st = {.body = sdsempty()};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "User-Agent: " WEB_UA);
    headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.8");
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    if (extra_header && extra_header[0]) headers = curl_slist_append(headers, extra_header);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields ? post_fields : "");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &st);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    long cto = (timeout_s > 0 && timeout_s <= 15) ? 4L : 8L;
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, cto);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_s > 0 ? timeout_s : 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (http_code_out) *http_code_out = code;

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        sds err = sdscatprintf(sdsempty(), "ERROR: curl %s", curl_easy_strerror(res));
        sdsfree(st.body);
        return err;
    }
    if (code >= 400) {
        sds err = sdscatprintf(sdsempty(), "ERROR: HTTP %ld for %s\n%.400s", code, url, st.body);
        sdsfree(st.body);
        return err;
    }
    return st.body;
}


/* Elo-style keyless extract: direct HTML → markdown/text (no Brave/Firecrawl on fetch) */

static sds strip_tags_decode(const char *in, size_t len) {
    sds out = sdsempty();
    int in_tag = 0;
    for (size_t i = 0; i < len; i++) {
        char c = in[i];
        if (c == '<') { in_tag = 1; continue; }
        if (in_tag) { if (c == '>') in_tag = 0; continue; }
        if (c == '&') {
            if (i + 5 < len && strncasecmp(in + i, "&nbsp;", 6) == 0) { out = sdscatlen(out, " ", 1); i += 5; continue; }
            if (i + 4 < len && strncasecmp(in + i, "&amp;", 5) == 0) { out = sdscatlen(out, "&", 1); i += 4; continue; }
            if (i + 3 < len && strncasecmp(in + i, "&lt;", 4) == 0) { out = sdscatlen(out, "<", 1); i += 3; continue; }
            if (i + 3 < len && strncasecmp(in + i, "&gt;", 4) == 0) { out = sdscatlen(out, ">", 1); i += 3; continue; }
            if (i + 5 < len && strncasecmp(in + i, "&quot;", 6) == 0) { out = sdscatlen(out, "\"", 1); i += 5; continue; }
            if (i + 4 < len && strncasecmp(in + i, "&#39;", 5) == 0) { out = sdscatlen(out, "'", 1); i += 4; continue; }
            if (i + 5 < len && strncasecmp(in + i, "&apos;", 6) == 0) { out = sdscatlen(out, "'", 1); i += 5; continue; }
            /* numeric &#NNN; or &#xHH; */
            if (i + 3 < len && in[i + 1] == '#') {
                size_t j = i + 2;
                int hex = 0;
                if (j < len && (in[j] == 'x' || in[j] == 'X')) { hex = 1; j++; }
                unsigned long v = 0;
                size_t start = j;
                while (j < len && j - start < 8) {
                    char d = in[j];
                    if (!hex && d >= '0' && d <= '9') { v = v * 10 + (unsigned)(d - '0'); j++; continue; }
                    if (hex && d >= '0' && d <= '9') { v = v * 16 + (unsigned)(d - '0'); j++; continue; }
                    if (hex && d >= 'a' && d <= 'f') { v = v * 16 + (unsigned)(d - 'a' + 10); j++; continue; }
                    if (hex && d >= 'A' && d <= 'F') { v = v * 16 + (unsigned)(d - 'A' + 10); j++; continue; }
                    break;
                }
                if (j > start && j < len && in[j] == ';' && v > 0 && v < 128) {
                    char ch = (char)v;
                    out = sdscatlen(out, &ch, 1);
                    i = j;
                    continue;
                }
            }
        }
        out = sdscatlen(out, &c, 1);
    }
    /* collapse whitespace lightly */
    sds clean = sdsempty();
    int space = 0;
    for (size_t i = 0; i < sdslen(out); i++) {
        char c = out[i];
        if (c == '\r') continue;
        if (c == '\t') c = ' ';
        if (c == ' ') {
            if (space) continue;
            space = 1;
            clean = sdscatlen(clean, " ", 1);
            continue;
        }
        if (c == '\n') {
            space = 1;
            clean = sdscatlen(clean, "\n", 1);
            continue;
        }
        space = 0;
        clean = sdscatlen(clean, &c, 1);
    }
    sdsfree(out);
    return clean;
}

static sds extract_title(const char *html) {
    const char *p = strcasestr(html, "<title");
    if (!p) return sdsnew("");
    p = strchr(p, '>');
    if (!p) return sdsnew("");
    p++;
    const char *end = strcasestr(p, "</title>");
    if (!end || end <= p) return sdsnew("");
    sds t = strip_tags_decode(p, (size_t)(end - p));
    /* single line */
    for (size_t i = 0; i < sdslen(t); i++) if (t[i] == '\n') t[i] = ' ';
    return t;
}

/* Prefer <article> / <main> / role="main" / content div (readability-lite) */
static sds prefer_main_html(const char *html) {
    const char *cands[] = {
        "<article", "<main", "role=\"main\"", "role='main'",
        "class=\"contents\"", "class='contents'", "id=\"content\"", "id='content'",
        "class=\"content\"", "class='content'", NULL
    };
    const char *best = NULL;
    size_t best_len = 0;
    for (int c = 0; cands[c]; c++) {
        const char *p = strcasestr(html, cands[c]);
        if (!p) continue;
        /* back up to opening '<' for attribute-based matches */
        if (cands[c][0] != '<') {
            while (p > html && *p != '<') p--;
            if (*p != '<') continue;
        }
        const char *tag_end = strchr(p, '>');
        if (!tag_end) continue;
        const char *close = NULL;
        if (strncasecmp(p, "<article", 8) == 0) close = strcasestr(tag_end, "</article>");
        else if (strncasecmp(p, "<main", 5) == 0) close = strcasestr(tag_end, "</main>");
        else {
            /* div/section window */
            close = p + 200000;
            if (close > html + strlen(html)) close = html + strlen(html);
        }
        if (!close || close <= tag_end) continue;
        size_t len = (size_t)(close - p);
        if (len > best_len && len > 200) {
            best = p;
            best_len = len;
        }
    }
    sds out;
    if (!best) out = sdsnew(html);
    else out = sdsnewlen(best, best_len > 400000 ? 400000 : best_len);

    /* curl.se and similar: strip obvious menu blocks */
    sds cleaned = sdsempty();
    const char *p = out;
    while (*p) {
        const char *menu = strcasestr(p, "class=\"menu\"");
        const char *menu2 = strcasestr(p, "class='menu'");
        const char *m = NULL;
        if (menu && menu2) m = menu < menu2 ? menu : menu2;
        else m = menu ? menu : menu2;
        if (!m) {
            cleaned = sdscat(cleaned, p);
            break;
        }
        /* back to tag start */
        const char *tag = m;
        while (tag > p && *tag != '<') tag--;
        cleaned = sdscatlen(cleaned, p, (size_t)(tag - p));
        /* skip until this div closes at nesting depth 0 — approximate: next 2x </div> after large block or 15k */
        const char *end = tag + 1;
        int depth = 1;
        while (*end && depth > 0) {
            const char *d1 = strcasestr(end, "<div");
            const char *d2 = strcasestr(end, "</div>");
            if (!d2) { end = tag + strlen(tag); break; }
            if (d1 && d1 < d2) { depth++; end = d1 + 4; }
            else { depth--; end = d2 + 6; }
            if ((size_t)(end - tag) > 30000) break;
        }
        p = end;
    }
    sdsfree(out);
    return cleaned;
}

/* Drop script/style/nav chrome blocks before conversion */
static sds strip_noise_blocks(const char *html) {
    sds out = sdsempty();
    const char *p = html;
    while (*p) {
        const char *s1 = strcasestr(p, "<script");
        const char *s2 = strcasestr(p, "<style");
        const char *s3 = strcasestr(p, "<noscript");
        const char *s4 = strcasestr(p, "<svg");
        const char *s5 = strcasestr(p, "<nav");
        const char *s6 = strcasestr(p, "<footer");
        const char *s7 = strcasestr(p, "<header");
        const char *s8 = strcasestr(p, "id=\"p-lang\"");
        const char *s9 = strcasestr(p, "id=\"p-lang-btn\"");
        const char *s10 = strcasestr(p, "class=\"vector-menu-content\"");
        const char *s11 = strcasestr(p, "id=\"toc\"");
        const char *next = NULL;
        const char *close = NULL;
        if (s1 && (!next || s1 < next)) { next = s1; close = "</script>"; }
        if (s2 && (!next || s2 < next)) { next = s2; close = "</style>"; }
        if (s3 && (!next || s3 < next)) { next = s3; close = "</noscript>"; }
        if (s4 && (!next || s4 < next)) { next = s4; close = "</svg>"; }
        if (s5 && (!next || s5 < next)) { next = s5; close = "</nav>"; }
        if (s6 && (!next || s6 < next)) { next = s6; close = "</footer>"; }
        if (s7 && (!next || s7 < next)) { next = s7; close = "</header>"; }
        /* Wikipedia language / TOC chrome: skip to next close div */
        if (s8 && (!next || s8 < next)) { next = s8; close = "</div>"; }
        if (s9 && (!next || s9 < next)) { next = s9; close = "</div>"; }
        if (s10 && (!next || s10 < next)) { next = s10; close = "</div>"; }
        if (s11 && (!next || s11 < next)) { next = s11; close = "</div>"; }
        if (!next) {
            out = sdscat(out, p);
            break;
        }
        out = sdscatlen(out, p, (size_t)(next - p));
        const char *c = strcasestr(next, close);
        if (!c) break;
        p = c + strlen(close);
    }
    return out;
}

/* Drop wiki language dumps / empty chrome from markdown text */
static sds strip_wiki_language_noise(sds md) {
    if (!md) return md;
    /* Remove common "N languages" dumps that leak as bullet lists of language names */
    sds out = sdsempty();
    const char *p = md;
    while (*p) {
        const char *line = p;
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        int drop = 0;
        if (len > 0) {
            if (strcasestr(line, "toggle the table of contents")) drop = 1;
            else if (strstr(line, " languages") && len < 40) drop = 1;
            else if (len < 40 && line[0] == '-' && (
                strstr(line, "Afrikaans") || strstr(line, "العربية") ||
                strstr(line, "Deutsch") || strstr(line, "Español") ||
                strstr(line, "Français") || strstr(line, "Русский") ||
                strstr(line, "中文") || strstr(line, "日本語") ||
                strstr(line, "Português") || strstr(line, "Italiano") ||
                strstr(line, "Polski") || strstr(line, "Nederlands") ||
                strstr(line, "Svenska") || strstr(line, "Suomi") ||
                strstr(line, "Ελληνικά") || strstr(line, "Türkçe")))
                drop = 1;
        }
        if (!drop) {
            out = sdscatlen(out, line, len);
            if (nl) out = sdscatlen(out, "\n", 1);
        }
        if (!nl) break;
        p = nl + 1;
    }
    sdsfree(md);
    return out;
}

/* Elo-like html → markdown-ish */
static sds html_to_markdown(const char *html_in, size_t max_chars, sds *title_out, const char **extractor_out) {
    if (title_out) *title_out = extract_title(html_in ? html_in : "");
    sds main = prefer_main_html(html_in ? html_in : "");
    if (extractor_out) {
        if (strcasestr(main, "<article") == main || strcasestr(main, "<article")) *extractor_out = "article/main";
        else if (strcasestr(main, "<main")) *extractor_out = "main";
        else *extractor_out = "basic";
    }
    sds cleaned = strip_noise_blocks(main);
    sdsfree(main);

    sds out = sdsempty();
    const char *p = cleaned;
    int space = 1;
    while (*p && (size_t)sdslen(out) < max_chars) {
        if (*p == '<') {
            if (strncasecmp(p, "<!--", 4) == 0) {
                const char *e = strstr(p + 4, "-->");
                p = e ? e + 3 : p + 1;
                continue;
            }
            /* links */
            if (strncasecmp(p, "<a ", 3) == 0 || strncasecmp(p, "<a\t", 3) == 0 || strncasecmp(p, "<a\n", 3) == 0) {
                const char *href = strcasestr(p, "href=");
                const char *tagend = strchr(p, '>');
                const char *aend = strcasestr(p, "</a>");
                sds url = sdsempty();
                if (href && tagend && href < tagend) {
                    href += 5;
                    char q = *href;
                    if (q == '"' || q == '\'') {
                        href++;
                        const char *ue = strchr(href, q);
                        if (ue) url = sdsnewlen(href, (size_t)(ue - href));
                    }
                }
                sds label = sdsempty();
                if (tagend && aend && aend > tagend) {
                    sdsfree(label);
                    label = strip_tags_decode(tagend + 1, (size_t)(aend - tagend - 1));
                }
                if (sdslen(label) && sdslen(url)) out = sdscatprintf(out, "[%s](%s)", label, url);
                else if (sdslen(label)) out = sdscatsds(out, label);
                else if (sdslen(url)) out = sdscatsds(out, url);
                sdsfree(label);
                sdsfree(url);
                p = aend ? aend + 4 : (tagend ? tagend + 1 : p + 1);
                space = 0;
                continue;
            }
            /* headings */
            if ((p[1] == 'h' || p[1] == 'H') && p[2] >= '1' && p[2] <= '6') {
                int level = p[2] - '0';
                const char *tagend = strchr(p, '>');
                char close[6] = {'<','/','h', (char)('0'+level), '>', 0};
                const char *hend = tagend ? strcasestr(tagend, close) : NULL;
                if (tagend && hend && hend > tagend) {
                    sds body = strip_tags_decode(tagend + 1, (size_t)(hend - tagend - 1));
                    out = sdscat(out, "\n");
                    for (int i = 0; i < level; i++) out = sdscatlen(out, "#", 1);
                    out = sdscatprintf(out, " %s\n", body);
                    sdsfree(body);
                    p = hend + 5;
                    space = 1;
                    continue;
                }
            }
            if (strncasecmp(p, "<li", 3) == 0) {
                const char *tagend = strchr(p, '>');
                const char *lend = tagend ? strcasestr(tagend, "</li>") : NULL;
                if (tagend && lend && lend > tagend) {
                    sds body = strip_tags_decode(tagend + 1, (size_t)(lend - tagend - 1));
                    out = sdscatprintf(out, "\n- %s", body);
                    sdsfree(body);
                    p = lend + 5;
                    space = 0;
                    continue;
                }
            }
            if (strncasecmp(p, "<br", 3) == 0 || strncasecmp(p, "<hr", 3) == 0) {
                if (!space) out = sdscatlen(out, "\n", 1);
                space = 1;
                const char *tagend = strchr(p, '>');
                p = tagend ? tagend + 1 : p + 1;
                continue;
            }
            if (strncasecmp(p, "</p", 3) == 0 || strncasecmp(p, "</div", 5) == 0 ||
                strncasecmp(p, "</section", 9) == 0 || strncasecmp(p, "</tr", 4) == 0 ||
                strncasecmp(p, "</ul", 4) == 0 || strncasecmp(p, "</ol", 4) == 0) {
                if (!space) out = sdscatlen(out, "\n", 1);
                space = 1;
            }
            const char *tagend = strchr(p, '>');
            p = tagend ? tagend + 1 : p + 1;
            continue;
        }
        char c = *p++;
        if (c == '\r') continue;
        if (c == '\n' || c == '\t') c = ' ';
        if (c == ' ') {
            if (space) continue;
            space = 1;
            out = sdscatlen(out, " ", 1);
            continue;
        }
        space = 0;
        out = sdscatlen(out, &c, 1);
    }
    sdsfree(cleaned);
    /* trim trailing space-ish */
    while (sdslen(out) && (out[sdslen(out)-1] == ' ' || out[sdslen(out)-1] == '\n'))
        sdsrange(out, 0, (ssize_t)sdslen(out) - 2);
    out = strip_wiki_language_noise(out);
    /* Drop nav-ish lines: many markdown links / bare pipes, little prose */
    {
        sds clean = sdsempty();
        const char *p = out;
        while (*p) {
            const char *nl = strchr(p, '\n');
            size_t len = nl ? (size_t)(nl - p) : strlen(p);
            int links = 0, letters = 0;
            for (size_t i = 0; i < len; i++) {
                if (p[i] == '[') links++;
                if ((p[i] >= 'a' && p[i] <= 'z') || (p[i] >= 'A' && p[i] <= 'Z')) letters++;
                            }
            int drop = 0;
            /* only kill obvious nav chrome, not article lines with a few links */
            if (links >= 6 && letters < links * 10) drop = 1;
            if (links >= 8) drop = 1;
            if (len > 200 && links >= 5 && letters < 60) drop = 1;
            if (links >= 4 && strstr(p, "API Overview") && strstr(p, "easy setopt")) drop = 1;
            if (links >= 3 && strstr(p, "](/libcurl/") && strstr(p, "API:") && len > 100) drop = 1;
            if (!drop) {
                clean = sdscatlen(clean, p, len);
                if (nl) clean = sdscatlen(clean, "\n", 1);
            }
            if (!nl) break;
            p = nl + 1;
        }
        sdsfree(out);
        out = clean;
    }
    return out;
}

sds html_to_text(const char *html, size_t max_chars) {
    sds title = NULL;
    const char *ext = NULL;
    sds md = html_to_markdown(html, max_chars ? max_chars : 12000, &title, &ext);
    sdsfree(title);
    /* strip markdown syntax to plain text */
    sds out = sdsempty();
    for (size_t i = 0; i < sdslen(md); i++) {
        if (md[i] == '#' && (i == 0 || md[i-1] == '\n')) {
            while (md[i] == '#' || md[i] == ' ') i++;
            if (i < sdslen(md)) i--;
            continue;
        }
        if (md[i] == '[') {
            /* [label](url) -> label */
            size_t j = i + 1;
            while (j < sdslen(md) && md[j] != ']') j++;
            if (j < sdslen(md) && j + 1 < sdslen(md) && md[j+1] == '(') {
                out = sdscatlen(out, md + i + 1, j - i - 1);
                size_t k = j + 2;
                while (k < sdslen(md) && md[k] != ')') k++;
                i = k;
                continue;
            }
        }
        out = sdscatlen(out, md + i, 1);
    }
    sdsfree(md);
    (void)ext;
    return out;
}

/* ---------- result row ---------- */
typedef struct {
    sds title;
    sds url;
    sds snippet;
} hit_t;

static void hit_free(hit_t *h) {
    if (!h) return;
    sdsfree(h->title);
    sdsfree(h->url);
    sdsfree(h->snippet);
    h->title = h->url = h->snippet = NULL;
}

static sds url_decode_lite(const char *s) {
    sds out = sdsempty();
    for (const char *p = s; *p; p++) {
        if (*p == '%' && isxdigit((unsigned char)p[1]) && isxdigit((unsigned char)p[2])) {
            char hex[3] = {p[1], p[2], 0};
            char c = (char)strtol(hex, NULL, 16);
            out = sdscatlen(out, &c, 1);
            p += 2;
        } else if (*p == '+') {
            out = sdscatlen(out, " ", 1);
        } else {
            out = sdscatlen(out, p, 1);
        }
    }
    return out;
}

/* Keyless search helpers (no Brave). */
static int ddg_looks_challenged(const char *html);

static int hit_add_unique(hit_t *hits, int n, int maxn, const char *url, const char *title) {
    if (!url || n >= maxn) return n;
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) return n;
    if (strstr(url, "duckduckgo.com") || strstr(url, "duck.com")) return n;
    if (strstr(url, "bing.com/ck/") || strstr(url, "microsoft.com")) {
        /* keep bing redirect targets only after decode; skip bing chrome */
    }
    for (int i = 0; i < n; i++) {
        if (hits[i].url && strcmp(hits[i].url, url) == 0) return n;
    }
    hits[n].url = sdsnew(url);
    hits[n].title = sdsnew(title && title[0] ? title : url);
    hits[n].snippet = sdsnew("");
    return n + 1;
}

static int parse_uddg_hits(const char *html, hit_t *hits, int maxn) {
    int n = 0;
    const char *p = html;
    while (n < maxn && (p = strstr(p, "uddg=")) != NULL) {
        p += 5;
        const char *end = p;
        while (*end && *end != '&' && *end != '"' && *end != '\'') end++;
        sds raw = sdsnewlen(p, (size_t)(end - p));
        sds link = url_decode_lite(raw);
        sdsfree(raw);
        /* title near </a> after this href */
        sds title = sdsnew("");
        const char *a_close = strstr(end, "</a>");
        const char *a_open_end = end;
        while (a_open_end > html && *a_open_end != '>') a_open_end--;
        if (*a_open_end == '>' && a_close && a_close > a_open_end) {
            sdsfree(title);
            title = html_to_text(a_open_end + 1, 200);
            size_t tl = (size_t)(a_close - (a_open_end + 1));
            if (tl < sdslen(title)) sdsrange(title, 0, (ssize_t)tl - 1);
        }
        n = hit_add_unique(hits, n, maxn, link, title);
        sdsfree(link);
        sdsfree(title);
        p = end;
    }
    return n;
}

/* Also parse plain result anchors: class="result__a" href="https://..." */
static int parse_result_a_hits(const char *html, hit_t *hits, int n, int maxn) {
    const char *p = html;
    while (n < maxn && (p = strcasestr(p, "result__a")) != NULL) {
        const char *href = strcasestr(p, "href=");
        if (!href || href - p > 200) { p += 9; continue; }
        href += 5;
        char q = *href;
        const char *u = href;
        const char *ue;
        if (q == '"' || q == '\'') {
            u = href + 1;
            ue = strchr(u, q);
        } else {
            ue = u;
            while (*ue && *ue != ' ' && *ue != '>') ue++;
        }
        if (!ue || ue <= u) { p += 9; continue; }
        sds raw = sdsnewlen(u, (size_t)(ue - u));
        sds link = raw;
        if (strstr(raw, "uddg=")) {
            const char *ud = strstr(raw, "uddg=");
            ud += 5;
            const char *e = ud;
            while (*e && *e != '&') e++;
            sds piece = sdsnewlen(ud, (size_t)(e - ud));
            sdsfree(raw);
            link = url_decode_lite(piece);
            sdsfree(piece);
        } else if (strncmp(raw, "http", 4) != 0) {
            sdsfree(raw);
            p += 9;
            continue;
        }
        const char *gt = strchr(ue, '>');
        const char *ac = gt ? strcasestr(gt, "</a>") : NULL;
        sds title = sdsnew("");
        if (gt && ac && ac > gt) {
            sdsfree(title);
            title = html_to_text(gt + 1, 200);
        }
        n = hit_add_unique(hits, n, maxn, link, title);
        sdsfree(link);
        sdsfree(title);
        p = ac ? ac + 4 : p + 9;
    }
    return n;
}

/* Wikipedia opensearch JSON — keyless stable fallback for benches/tests */
static int search_wikipedia_one(const char *query, hit_t *hits, int n, int maxn) {
    if (!query || !query[0] || n >= maxn) return n;
    CURL *curl = curl_easy_init();
    if (!curl) return n;
    char *enc = curl_easy_escape(curl, query, 0);
    sds url = sdscatprintf(sdsempty(),
        "https://en.wikipedia.org/w/api.php?action=opensearch&search=%s&limit=%d&namespace=0&format=json",
        enc, maxn - n);
    curl_free(enc);
    curl_easy_cleanup(curl);
    long code = 0;
    sds body = http_get(url, "Accept: application/json", 20, &code);
    sdsfree(url);
    if (!body || strncmp(body, "ERROR:", 6) == 0) {
        sdsfree(body);
        return n;
    }
    cJSON *root = cJSON_Parse(body);
    sdsfree(body);
    if (!root || !cJSON_IsArray(root) || cJSON_GetArraySize(root) < 4) {
        cJSON_Delete(root);
        return n;
    }
    cJSON *titles = cJSON_GetArrayItem(root, 1);
    cJSON *urls = cJSON_GetArrayItem(root, 3);
    if (cJSON_IsArray(titles) && cJSON_IsArray(urls)) {
        int m = cJSON_GetArraySize(urls);
        for (int i = 0; i < m && n < maxn; i++) {
            cJSON *uj = cJSON_GetArrayItem(urls, i);
            cJSON *tj = cJSON_GetArrayItem(titles, i);
            const char *u = (uj && cJSON_IsString(uj)) ? uj->valuestring : NULL;
            const char *ti = (tj && cJSON_IsString(tj)) ? tj->valuestring : NULL;
            if (!u) continue;
            n = hit_add_unique(hits, n, maxn, u, ti ? ti : u);
        }
    }
    cJSON_Delete(root);
    return n;
}

static int search_wikipedia(const char *query, hit_t *hits, int maxn) {
    int n = search_wikipedia_one(query, hits, 0, maxn);
    if (n > 0) return n;
    /* fallback: try significant tokens so multi-word queries still resolve keyless */
    if (!query) return 0;
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", query);
    char *save = NULL;
    char *tok = strtok_r(buf, " 	", &save);
    while (tok && n < maxn) {
        if (strlen(tok) >= 3) {
            n = search_wikipedia_one(tok, hits, n, maxn);
            if (n > 0) break;
        }
        tok = strtok_r(NULL, " 	", &save);
    }
    return n;
}

/* DuckDuckGo lite (often less bot-hostile than /html/) */
static int search_ddg_lite(const char *query, hit_t *hits, int maxn) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;
    char *enc = curl_easy_escape(curl, query, 0);
    sds url = sdscatprintf(sdsempty(), "https://lite.duckduckgo.com/lite/?q=%s", enc);
    curl_free(enc);
    curl_easy_cleanup(curl);
    long code = 0;
    sds html = http_get(url, NULL, 8, &code);
    sdsfree(url);
    if (!html || strncmp(html, "ERROR:", 6) == 0) {
        sdsfree(html);
        return 0;
    }
    int n = 0;
    /* lite uses result-link or uddg too; also plain <a rel="nofollow" href="http..."> */
    if (ddg_looks_challenged(html) && !strcasestr(html, "result__a") && !strstr(html, "uddg=")) {
        /* challenged / empty lite page */
    }
    n = parse_uddg_hits(html, hits, maxn);
    n = parse_result_a_hits(html, hits, n, maxn);
    const char *p = html;
    while (n < maxn && (p = strstr(p, "href=\"")) != NULL) {
        p += 6;
        const char *e = strchr(p, '"');
        if (!e) break;
        sds link = sdsnewlen(p, (size_t)(e - p));
        if (strncmp(link, "http", 4) == 0 && !strstr(link, "duckduckgo") && !strstr(link, "duck.com")) {
            /* title: next >text< */
            const char *gt = strchr(e, '>');
            const char *lt = gt ? strchr(gt + 1, '<') : NULL;
            sds title = sdsnew("");
            if (gt && lt && lt > gt + 1) {
                sdsfree(title);
                title = html_to_text(gt + 1, 160);
            }
            /* skip nav-ish short links */
            if (sdslen(title) > 2 && !strstr(link, "javascript:"))
                n = hit_add_unique(hits, n, maxn, link, title);
            sdsfree(title);
        }
        sdsfree(link);
        p = e + 1;
    }
    sdsfree(html);
    return n;
}

static int search_ddg_html(const char *query, hit_t *hits, int maxn) {
    /* POST form — GET often returns bot challenge (HTTP 202, no results). No Brave. */
    CURL *curl = curl_easy_init();
    if (!curl) return 0;
    char *enc = curl_easy_escape(curl, query, 0);
    sds fields = sdscatprintf(sdsempty(), "q=%s&b=", enc);
    curl_free(enc);
    curl_easy_cleanup(curl);

    long code = 0;
    sds html = http_post("https://html.duckduckgo.com/html/", fields, NULL, 8, &code);
    sdsfree(fields);
    if (!html || strncmp(html, "ERROR:", 6) == 0) {
        sdsfree(html);
        return 0;
    }
    int n = parse_uddg_hits(html, hits, maxn);
    n = parse_result_a_hits(html, hits, n, maxn);
    sdsfree(html);
    return n;
}


/* Decode common HTML entities inside URLs (&amp; etc.) */
static sds url_html_decode(const char *u) {
    if (!u) return sdsnew("");
    sds out = sdsempty();
    for (const char *p = u; *p; ) {
        if (strncmp(p, "&amp;", 5) == 0) { out = sdscatlen(out, "&", 1); p += 5; continue; }
        if (strncmp(p, "&#38;", 5) == 0) { out = sdscatlen(out, "&", 1); p += 5; continue; }
        if (strncmp(p, "&quot;", 6) == 0) { out = sdscatlen(out, "\"", 1); p += 6; continue; }
        if (strncmp(p, "&#39;", 5) == 0) { out = sdscatlen(out, "'", 1); p += 5; continue; }
        out = sdscatlen(out, p, 1);
        p++;
    }
    return out;
}

/* Startpage HTML — keyless; often works when DDG challenge-walls us. No API key. */
static int search_startpage(const char *query, hit_t *hits, int maxn) {
    if (!query || !query[0] || maxn <= 0) return 0;
    CURL *curl = curl_easy_init();
    if (!curl) return 0;
    char *enc = curl_easy_escape(curl, query, 0);
    sds url = sdscatprintf(sdsempty(),
        "https://www.startpage.com/sp/search?query=%s&cat=web&pl=opensearch", enc);
    curl_free(enc);
    curl_easy_cleanup(curl);
    long code = 0;
    sds html = http_get(url, "Accept: text/html", 12, &code);
    sdsfree(url);
    if (!html || strncmp(html, "ERROR:", 6) == 0) {
        sdsfree(html);
        return 0;
    }
    int n = 0;
    const char *p = html;
    while (n < maxn && (p = strcasestr(p, "result-link")) != NULL) {
        const char *href = strcasestr(p, "href=");
        if (!href || href - p > 180) { p += 11; continue; }
        href += 5;
        char qch = *href;
        const char *u = href;
        const char *ue = NULL;
        if (qch == '"' || qch == '\'') {
            u = href + 1;
            ue = strchr(u, qch);
        } else {
            ue = u;
            while (*ue && *ue != ' ' && *ue != '>') ue++;
        }
        if (!ue || ue <= u) { p += 11; continue; }
        sds link_raw = sdsnewlen(u, (size_t)(ue - u));
        sds link = url_html_decode(link_raw);
        sdsfree(link_raw);
        if (strncmp(link, "http", 4) != 0 || strstr(link, "startpage.com") || strstr(link, "cdn.startpage")) {
            sdsfree(link);
            p = ue;
            continue;
        }
        /* title from h2 inside the anchor if present */
        sds title = sdsnew("");
        const char *gt = strchr(ue, '>');
        const char *ac = gt ? strcasestr(gt, "</a>") : NULL;
        if (gt && ac && ac > gt) {
            const char *h2 = strcasestr(gt, "<h2");
            if (h2 && h2 < ac) {
                const char *h2e = strchr(h2, '>');
                const char *h2c = h2e ? strcasestr(h2e, "</h2>") : NULL;
                if (h2e && h2c && h2c > h2e) {
                    sdsfree(title);
                    title = strip_tags_decode(h2e + 1, (size_t)(h2c - h2e - 1));
                }
            }
            if (sdslen(title) < 3) {
                sdsfree(title);
                title = strip_tags_decode(gt + 1, (size_t)(ac - gt - 1));
            }
        }
        /* drop CSS-emotion garbage titles */
        if (sdslen(title) > 0 && title[0] != '.' && !strstr(title, "{display:") && sdslen(title) < 200)
            n = hit_add_unique(hits, n, maxn, link, title);
        sdsfree(link);
        sdsfree(title);
        p = ac ? ac + 4 : ue + 1;
    }
    sdsfree(html);
    return n;
}

static int ddg_looks_challenged(const char *html) {
    if (!html) return 1;
    if (strcasestr(html, "challenge-form") || strcasestr(html, "anomaly-modal") ||
        strcasestr(html, "Unfortunately, bots use DuckDuckGo too") ||
        strcasestr(html, "c-frame") ) return 1;
    if (!strstr(html, "uddg=") && !strcasestr(html, "result__a") && !strcasestr(html, "result-link"))
        return 1;
    return 0;
}

static int is_codeish(const char *q) {
    if (!q) return 0;
    const char *keys[] = {
        "mcp", "github", "api", "libcurl", "curl", "clang", "rust", "python", "sdk",
        "openclaw", "nodejs", "typescript", "c++", "http", "npm", "repo",
        "server", "cli", "framework", "tutorial", "tokio", "async", "requests",
        "fastapi", "django", "pytorch", "tensorflow", "llvm", "openssl", "json",
        "websocket", "graphql", "kubernetes", "docker", "nginx", "terraform",
        "ansible", "kafka", "prometheus", "grafana", "prisma", "nextjs", "django",
        "flask", "pytest", "grpc", "protobuf", "tailwind", "vue", "svelte", NULL
    };
    for (int i = 0; keys[i]; i++) if (strcasestr(q, keys[i])) return 1;
    return 0;
}

/* GitHub full-phrase search often returns junk (termux scripts). Prefer product token. */
static void github_query_simplify(const char *query, char *out, size_t outsz) {
    if (!out || outsz == 0) return;
    out[0] = 0;
    if (!query || !query[0]) return;
    if (strcasestr(query, "openclaw")) { snprintf(out, outsz, "openclaw"); return; }
    if (strcasestr(query, "libcurl") || (strcasestr(query, "curl") && strcasestr(query, "lib"))) {
        snprintf(out, outsz, "libcurl");
        return;
    }
    if (strcasestr(query, "tokio")) { snprintf(out, outsz, "tokio"); return; }
    if (strcasestr(query, "redis")) { snprintf(out, outsz, "redis"); return; }
    if (strcasestr(query, "react")) { snprintf(out, outsz, "facebook/react"); return; }
    if (strcasestr(query, "sqlite")) { snprintf(out, outsz, "sqlite"); return; }
    if (strcasestr(query, "requests") && strcasestr(query, "python")) {
        snprintf(out, outsz, "psf/requests");
        return;
    }
    if (strcasestr(query, "fastapi")) { snprintf(out, outsz, "fastapi"); return; }
    if (strcasestr(query, "openclaw")) { snprintf(out, outsz, "openclaw"); return; }
    /* first token >= 3 chars that is not a stopword */
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", query);
    char *save = NULL;
    for (char *t = strtok_r(buf, " \t", &save); t; t = strtok_r(NULL, " \t", &save)) {
        if (strlen(t) < 3) continue;
        if (!strcasecmp(t, "the") || !strcasecmp(t, "and") || !strcasecmp(t, "for") ||
            !strcasecmp(t, "with") || !strcasecmp(t, "how") || !strcasecmp(t, "what") ||
            !strcasecmp(t, "docs") || !strcasecmp(t, "documentation") || !strcasecmp(t, "tutorial") ||
            !strcasecmp(t, "simple") || !strcasecmp(t, "example") || !strcasecmp(t, "library") ||
            !strcasecmp(t, "async") || !strcasecmp(t, "runtime") || !strcasecmp(t, "overview"))
            continue;
        snprintf(out, outsz, "%s", t);
        return;
    }
    snprintf(out, outsz, "%s", query);
}

typedef struct {
    const char *needle;
    const char *url;
    const char *title;
} known_doc_t;

/* High-quality keyless seeds for common product/doc queries (no Brave). */
static const known_doc_t KNOWN_DOCS[] = {
    {"libcurl", "https://curl.se/libcurl/c/libcurl-tutorial.html", "libcurl tutorial (curl.se)"},
    {"libcurl", "https://curl.se/libcurl/c/", "libcurl - the multiprotocol file transfer library"},
    {"libcurl", "https://github.com/curl/curl", "curl/curl"},
    {"curl tutorial", "https://curl.se/libcurl/c/libcurl-tutorial.html", "libcurl tutorial (curl.se)"},
    {"openclaw", "https://github.com/openclaw/openclaw", "openclaw/openclaw"},
    {"openclaw", "https://docs.openclaw.ai", "OpenClaw documentation"},
    {"tokio", "https://tokio.rs", "Tokio - asynchronous Rust runtime"},
    {"tokio", "https://github.com/tokio-rs/tokio", "tokio-rs/tokio"},
    {"python requests", "https://docs.python-requests.org/", "Requests: HTTP for Humans"},
    {"python requests", "https://github.com/psf/requests", "psf/requests"},
    {"requests library", "https://docs.python-requests.org/", "Requests: HTTP for Humans"},
    {"fastapi", "https://fastapi.tiangolo.com/", "FastAPI framework"},
    {"fastapi", "https://github.com/tiangolo/fastapi", "tiangolo/fastapi"},
    {"webpack", "https://webpack.js.org/guides/code-splitting/", "Webpack code splitting guide"},
    {"webpack", "https://webpack.js.org/", "webpack"},
    {"webpack", "https://github.com/webpack/webpack", "webpack/webpack"},
    {"code splitting", "https://webpack.js.org/guides/code-splitting/", "Webpack code splitting guide"},
    {"kubernetes ingress", "https://kubernetes.io/docs/concepts/services-networking/ingress/", "Kubernetes Ingress concept"},
    {"kubernetes ingress", "https://github.com/kubernetes/ingress-nginx", "kubernetes/ingress-nginx"},
    {"ingress nginx", "https://kubernetes.github.io/ingress-nginx/", "NGINX Ingress Controller docs"},
    {"ingress nginx", "https://github.com/kubernetes/ingress-nginx", "kubernetes/ingress-nginx"},
    {"kubernetes", "https://kubernetes.io/docs/home/", "Kubernetes documentation"},
    {"example domain", "https://www.iana.org/domains/reserved", "IANA Reserved Domains"},
    {"example.com", "https://example.com", "Example Domain"},
    {"iana", "https://www.iana.org/domains/reserved", "IANA Reserved Domains"},
    {"http protocol", "https://developer.mozilla.org/en-US/docs/Web/HTTP", "HTTP - MDN"},
    {"openssl", "https://www.openssl.org/docs/", "OpenSSL documentation"},
    {"docker compose", "https://docs.docker.com/compose/", "Docker Compose docs"},
    {"postgres", "https://www.postgresql.org/docs/current/", "PostgreSQL documentation"},
    {"sqlite", "https://www.sqlite.org/docs.html", "SQLite documentation"},
    {"sqlite wal", "https://www.sqlite.org/wal.html", "SQLite Write-Ahead Logging"},
    {"wal mode", "https://www.sqlite.org/wal.html", "SQLite Write-Ahead Logging"},
    {"redis", "https://redis.io/docs/latest/develop/pubsub/", "Redis Pub/Sub docs"},
    {"redis", "https://redis.io/docs/", "Redis documentation"},
    {"redis", "https://github.com/redis/redis", "redis/redis"},
    {"pub sub", "https://redis.io/docs/latest/develop/pubsub/", "Redis Pub/Sub docs"},
    {"react", "https://react.dev/reference/react/useEffect", "React useEffect reference"},
    {"useeffect", "https://react.dev/reference/react/useEffect", "React useEffect reference"},
    {"react", "https://react.dev/", "React documentation"},
    {"react", "https://github.com/facebook/react", "facebook/react"},
    {"nodejs", "https://nodejs.org/docs/latest/api/", "Node.js API docs"},
    {"node.js", "https://nodejs.org/docs/latest/api/", "Node.js API docs"},
    {"typescript", "https://www.typescriptlang.org/docs/", "TypeScript documentation"},
    {"golang", "https://go.dev/doc/", "Go documentation"},
    {"go module", "https://go.dev/doc/", "Go documentation"},
    {"rust book", "https://doc.rust-lang.org/book/", "The Rust Programming Language"},
    {"mdn", "https://developer.mozilla.org/", "MDN Web Docs"},
    {"jwt", "https://jwt.io/introduction", "Introduction to JSON Web Tokens"},
    {"oauth", "https://oauth.net/2/", "OAuth 2.0"},
    {"nginx", "https://nginx.org/en/docs/", "nginx documentation"},
    {"nginx", "https://github.com/nginx/nginx", "nginx/nginx"},
    {"postgres", "https://www.postgresql.org/docs/current/tutorial.html", "PostgreSQL tutorial"},
    {"prisma", "https://www.prisma.io/docs", "Prisma documentation"},
    {"nextjs", "https://nextjs.org/docs", "Next.js documentation"},
    {"next.js", "https://nextjs.org/docs", "Next.js documentation"},
    {"vue", "https://vuejs.org/guide/introduction.html", "Vue.js guide"},
    {"svelte", "https://svelte.dev/docs", "Svelte documentation"},
    {"tailwind", "https://tailwindcss.com/docs", "Tailwind CSS docs"},
    {"pytest", "https://docs.pytest.org/", "pytest documentation"},
    {"django", "https://docs.djangoproject.com/", "Django documentation"},
    {"flask", "https://flask.palletsprojects.com/", "Flask documentation"},
    {"grpc", "https://grpc.io/docs/", "gRPC documentation"},
    {"protobuf", "https://protobuf.dev/", "Protocol Buffers documentation"},
    {"elasticsearch", "https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html", "Elasticsearch reference"},
    {"kafka", "https://kafka.apache.org/documentation/", "Apache Kafka documentation"},
    {"prometheus", "https://prometheus.io/docs/introduction/overview/", "Prometheus documentation"},
    {"grafana", "https://grafana.com/docs/", "Grafana documentation"},
    {"terraform", "https://developer.hashicorp.com/terraform/docs", "Terraform documentation"},
    {"ansible", "https://docs.ansible.com/", "Ansible documentation"},
    {"github actions", "https://docs.github.com/en/actions", "GitHub Actions documentation"},
    {"semver", "https://semver.org/", "Semantic Versioning"},
    {"rfc 9110", "https://www.rfc-editor.org/rfc/rfc9110", "RFC 9110 HTTP Semantics"},
    {NULL, NULL, NULL}
};

static int seed_known_docs(const char *query, hit_t *hits, int n, int maxn) {
    if (!query || !hits || maxn <= 0) return n;
    for (int i = 0; KNOWN_DOCS[i].needle; i++) {
        if (!strcasestr(query, KNOWN_DOCS[i].needle)) continue;
        n = hit_add_unique(hits, n, maxn, KNOWN_DOCS[i].url, KNOWN_DOCS[i].title);
        if (n >= maxn) break;
    }
    return n;
}

static int wiki_hits_look_weak(const char *query, hit_t *hits, int n) {
    if (n <= 0) return 1;
    char qbuf[256];
    snprintf(qbuf, sizeof(qbuf), "%s", query ? query : "");
    for (char *c = qbuf; *c; c++) if (*c >= 'A' && *c <= 'Z') *c = (char)(*c - 'A' + 'a');
    /* require at least one hit title/url sharing a meaningful token with query */
    char *save = NULL;
    char *toks[8];
    int nt = 0;
    char qcopy[256];
    snprintf(qcopy, sizeof(qcopy), "%s", qbuf);
    for (char *t = strtok_r(qcopy, " \t", &save); t && nt < 8; t = strtok_r(NULL, " \t", &save)) {
        if (strlen(t) >= 4) toks[nt++] = t;
    }
    if (nt == 0) return 0;
    int good = 0;
    for (int i = 0; i < n; i++) {
        char hay[512];
        snprintf(hay, sizeof(hay), " %s %s ", hits[i].title ? hits[i].title : "", hits[i].url ? hits[i].url : "");
        for (char *c = hay; *c; c++) {
            if (*c >= 'A' && *c <= 'Z') *c = (char)(*c - 'A' + 'a');
            if (*c == '_' || *c == '-' || *c == '/') *c = ' ';
        }
        int hit = 0;
        for (int t = 0; t < nt; t++) {
            /* whole-token-ish: space-delimited contains " tok " */
            char needle[128];
            snprintf(needle, sizeof(needle), " %s ", toks[t]);
            if (strstr(hay, needle)) { hit = 1; break; }
            /* exact title equality */
            if (hits[i].title) {
                char tt[256];
                snprintf(tt, sizeof(tt), "%s", hits[i].title);
                for (char *c = tt; *c; c++) if (*c >= 'A' && *c <= 'Z') *c = (char)(*c - 'A' + 'a');
                if (!strcmp(tt, toks[t])) { hit = 1; break; }
            }
        }
        if (hit) good++;
        /* hard reject common false friends */
        if (hits[i].title && (strcasestr(hits[i].title, "Redistribution") ||
            strcasestr(hits[i].title, "Squirrel") || strcasestr(hits[i].title, "Chris Squire"))) {
            /* not a good product match */
            if (good > 0) good--;
        }
    }
    return good == 0;
}

/* GitHub public search → hits (keyless). Used before Wikipedia for code-ish queries. */
static int search_github_hits(const char *query, hit_t *hits, int maxn) {
    if (!query || !query[0] || maxn <= 0) return 0;
    char gbuf[128];
    github_query_simplify(query, gbuf, sizeof(gbuf));
    const char *gq = gbuf[0] ? gbuf : query;
    CURL *curl = curl_easy_init();
    if (!curl) return 0;
    char *enc = curl_easy_escape(curl, gq, 0);
    sds url = sdscatprintf(sdsempty(),
        "https://api.github.com/search/repositories?q=%s&per_page=%d&sort=stars",
        enc, maxn > 10 ? 10 : maxn);
    curl_free(enc);
    curl_easy_cleanup(curl);
    long code = 0;
    /* GitHub wants an identifiable UA; browser UA can get odd rate-limit behavior. */
    sds body = http_get(url, "Accept: application/vnd.github.v3+json", 25, &code);
    sdsfree(url);
    if (!body || strncmp(body, "ERROR:", 6) == 0) {
        sdsfree(body);
        return 0;
    }
    cJSON *json = cJSON_Parse(body);
    sdsfree(body);
    if (!json) return 0;
    typedef struct { hit_t h; int score; } gh_scored_t;
    gh_scored_t scored[16];
    int sn = 0;
    cJSON *items = cJSON_GetObjectItem(json, "items");
    if (items && cJSON_IsArray(items)) {
        int m = cJSON_GetArraySize(items);
        for (int i = 0; i < m && sn < 16; i++) {
            cJSON *item = cJSON_GetArrayItem(items, i);
            cJSON *fn = cJSON_GetObjectItem(item, "full_name");
            cJSON *hu = cJSON_GetObjectItem(item, "html_url");
            cJSON *ds = cJSON_GetObjectItem(item, "description");
            cJSON *st = cJSON_GetObjectItem(item, "stargazers_count");
            const char *full = (fn && cJSON_IsString(fn)) ? fn->valuestring : NULL;
            const char *html = (hu && cJSON_IsString(hu)) ? hu->valuestring : NULL;
            const char *desc = (ds && cJSON_IsString(ds)) ? ds->valuestring : "";
            if (!html) continue;
            int score = 0;
            /* token overlap with query / simplified query */
            char qcopy[256];
            snprintf(qcopy, sizeof(qcopy), "%s", query);
            for (char *c = qcopy; *c; c++) if (*c >= 'A' && *c <= 'Z') *c = (char)(*c - 'A' + 'a');
            char hay[512];
            snprintf(hay, sizeof(hay), "%s %s %s", full ? full : "", html, desc ? desc : "");
            for (char *c = hay; *c; c++) if (*c >= 'A' && *c <= 'Z') *c = (char)(*c - 'A' + 'a');
            char *save = NULL;
            for (char *t = strtok_r(qcopy, " \t-_/.", &save); t; t = strtok_r(NULL, " \t-_/.", &save)) {
                if (strlen(t) < 3) continue;
                if (!strcasecmp(t, "the") || !strcasecmp(t, "and") || !strcasecmp(t, "for") ||
                    !strcasecmp(t, "with") || !strcasecmp(t, "how") || !strcasecmp(t, "what"))
                    continue;
                if (strstr(hay, t)) score += 4;
                /* exact repo name match bonus */
                if (full) {
                    char fnl[256];
                    snprintf(fnl, sizeof(fnl), "%s", full);
                    for (char *c = fnl; *c; c++) if (*c >= 'A' && *c <= 'Z') *c = (char)(*c - 'A' + 'a');
                    if (strstr(fnl, t)) score += 6;
                    /* owner/name ends with /token */
                    char tail[128];
                    snprintf(tail, sizeof(tail), "/%s", t);
                    if (strstr(fnl, tail)) score += 10;
                }
            }
            if (st && cJSON_IsNumber(st)) {
                if (st->valuedouble > 50000) score += 3;
                else if (st->valuedouble > 5000) score += 2;
                else if (st->valuedouble > 500) score += 1;
            }
            scored[sn].h.url = sdsnew(html);
            scored[sn].h.title = sdsnew(full ? full : html);
            scored[sn].h.snippet = sdsnew(desc && desc[0] ? desc : "");
            scored[sn].score = score;
            sn++;
        }
    }
    cJSON_Delete(json);
    /* sort by score desc */
    for (int i = 1; i < sn; i++) {
        gh_scored_t key = scored[i];
        int j = i - 1;
        while (j >= 0 && scored[j].score < key.score) {
            scored[j + 1] = scored[j];
            j--;
        }
        scored[j + 1] = key;
    }
    int n = 0;
    for (int i = 0; i < sn && n < maxn; i++) {
        /* skip very weak off-topic repos when better matches exist */
        if (i > 0 && scored[i].score <= 0 && scored[0].score >= 10) {
            hit_free(&scored[i].h);
            continue;
        }
        hits[n] = scored[i].h;
        n++;
    }
    /* free unused */
    for (int i = 0; i < sn; i++) {
        int kept = 0;
        for (int k = 0; k < n; k++) if (hits[k].url == scored[i].h.url) { kept = 1; break; }
        if (!kept) hit_free(&scored[i].h);
    }
    return n;
}

/* Keyless engines only (no Brave). Prefer broader web when DDG works; Wikipedia always as stable fallback. */
static int seeds_cover_query(const char *query) {
    /* true if every >=4-char query token is either stopword or appears in a matching seed needle/url/title */
    if (!query) return 1;
    char qcopy[256];
    snprintf(qcopy, sizeof(qcopy), "%s", query);
    for (char *c = qcopy; *c; c++) if (*c >= 'A' && *c <= 'Z') *c = (char)(*c - 'A' + 'a');
    char *save = NULL;
    for (char *tk = strtok_r(qcopy, " \t", &save); tk; tk = strtok_r(NULL, " \t", &save)) {
        if (strlen(tk) < 4) continue;
        if (!strcasecmp(tk, "with") || !strcasecmp(tk, "what") || !strcasecmp(tk, "how") ||
            !strcasecmp(tk, "does") || !strcasecmp(tk, "work") || !strcasecmp(tk, "tutorial") ||
            !strcasecmp(tk, "docs") || !strcasecmp(tk, "documentation") || !strcasecmp(tk, "example") ||
            !strcasecmp(tk, "simple") || !strcasecmp(tk, "guide") || !strcasecmp(tk, "latest") ||
            !strcasecmp(tk, "using") || !strcasecmp(tk, "into") || !strcasecmp(tk, "from") ||
            !strcasecmp(tk, "that") || !strcasecmp(tk, "this") || !strcasecmp(tk, "about") ||
            !strcasecmp(tk, "mode") || !strcasecmp(tk, "library") || !strcasecmp(tk, "setup"))
            continue;
        int covered = 0;
        for (int i = 0; KNOWN_DOCS[i].needle; i++) {
            if (!strcasestr(query, KNOWN_DOCS[i].needle)) continue;
            char hay[512];
            snprintf(hay, sizeof(hay), "%s %s %s",
                     KNOWN_DOCS[i].needle,
                     KNOWN_DOCS[i].url ? KNOWN_DOCS[i].url : "",
                     KNOWN_DOCS[i].title ? KNOWN_DOCS[i].title : "");
            for (char *c = hay; *c; c++) if (*c >= 'A' && *c <= 'Z') *c = (char)(*c - 'A' + 'a');
            if (strstr(hay, tk)) { covered = 1; break; }
        }
        if (!covered) return 0;
    }
    return 1;
}

static int search_keyless(const char *query, hit_t *hits, int maxn, const char **engine_out) {
    /* Known product/docs seeds first (stable quality without Brave). */
    int n = seed_known_docs(query, hits, 0, maxn);
    if (n >= 2 && seeds_cover_query(query)) {
        if (engine_out) *engine_out = "known-docs";
        return n;
    }

    /* Open web: Startpage first when DDG is usually challenge-walled (faster + better).
       Keep DDG as optional secondary. No Brave. */
    int base = n;
    {
        int n_sp = search_startpage(query, hits + n, maxn - n);
        if (n_sp > 0) {
            n += n_sp;
            if (engine_out) *engine_out = base ? "known-docs+startpage" : "startpage";
            return n;
        }
    }
    int n_ddg = search_ddg_html(query, hits + n, maxn - n);
    if (n_ddg > 0) {
        n += n_ddg;
        if (engine_out) *engine_out = base ? "known-docs+duckduckgo-html" : "duckduckgo-html";
        return n;
    }
    n_ddg = search_ddg_lite(query, hits + n, maxn - n);
    if (n_ddg > 0) {
        n += n_ddg;
        if (engine_out) *engine_out = base ? "known-docs+duckduckgo-lite" : "duckduckgo-lite";
        return n;
    }
    int conceptual = (strcasestr(query, "what is") || strcasestr(query, "who is") ||
                      strcasestr(query, "define ") || strcasestr(query, "meaning of"));

    /* Conceptual questions: try strong Wikipedia before GitHub star noise. */
    if (conceptual) {
        hit_t whits[10];
        memset(whits, 0, sizeof(whits));
        int wn = search_wikipedia(query, whits, maxn);
        if (wn > 0 && !wiki_hits_look_weak(query, whits, wn)) {
            for (int i = 0; i < wn && n < maxn; i++)
                n = hit_add_unique(hits, n, maxn, whits[i].url, whits[i].title);
            for (int i = 0; i < wn; i++) hit_free(&whits[i]);
            if (n > base) {
                if (engine_out) *engine_out = base ? "known-docs+wikipedia-opensearch" : "wikipedia-opensearch";
                return n;
            }
        } else {
            for (int i = 0; i < wn; i++) hit_free(&whits[i]);
        }
    }

    /* Code/product queries: GitHub before Wikipedia (avoids OpenClaw→OpenCL junk). */
    if (is_codeish(query)) {
        int n_gh = search_github_hits(query, hits + n, maxn - n);
        if (n_gh > 0) {
            n += n_gh;
            if (engine_out) *engine_out = base ? "known-docs+github-repos" : "github-repos";
            return n;
        }
    }
    {
        hit_t whits[10];
        memset(whits, 0, sizeof(whits));
        int wn = search_wikipedia(query, whits, maxn);
        if (wn > 0 && !wiki_hits_look_weak(query, whits, wn)) {
            for (int i = 0; i < wn && n < maxn; i++) {
                n = hit_add_unique(hits, n, maxn, whits[i].url, whits[i].title);
            }
            for (int i = 0; i < wn; i++) hit_free(&whits[i]);
            if (n > base) {
                if (engine_out) *engine_out = base ? "known-docs+wikipedia-opensearch" : "wikipedia-opensearch";
                return n;
            }
        } else {
            for (int i = 0; i < wn; i++) hit_free(&whits[i]);
        }
    }
    /* last chance github — only for technical/product queries (not local/coffee/PESEL spam) */
    if (is_codeish(query)) {
        int n_gh = search_github_hits(query, hits + n, maxn - n);
        if (n_gh > 0) {
            /* require at least one hit with token overlap vs query */
            int useful = 0;
            char qbuf[256];
            snprintf(qbuf, sizeof(qbuf), "%s", query);
            for (char *c = qbuf; *c; c++) if (*c >= 'A' && *c <= 'Z') *c = (char)(*c - 'A' + 'a');
            for (int i = 0; i < n_gh; i++) {
                char hay[512];
                snprintf(hay, sizeof(hay), "%s %s", hits[n + i].title ? hits[n + i].title : "",
                         hits[n + i].url ? hits[n + i].url : "");
                for (char *c = hay; *c; c++) if (*c >= 'A' && *c <= 'Z') *c = (char)(*c - 'A' + 'a');
                char *save = NULL; char qcopy[256];
                snprintf(qcopy, sizeof(qcopy), "%s", qbuf);
                for (char *tk = strtok_r(qcopy, " 	", &save); tk; tk = strtok_r(NULL, " 	", &save)) {
                    if (strlen(tk) < 4) continue;
                    if (strstr(hay, tk)) { useful = 1; break; }
                }
                if (useful) break;
            }
            if (useful) {
                n += n_gh;
                if (engine_out) *engine_out = base ? "known-docs+github-repos" : "github-repos";
                return n;
            }
            for (int i = 0; i < n_gh; i++) hit_free(&hits[n + i]);
        }
    }
    if (n > 0) {
        if (engine_out) *engine_out = "known-docs";
        return n;
    }
    /* DuckDuckGo Instant Answer JSON (keyless) */
    {
        CURL *curl = curl_easy_init();
        if (curl) {
            char *enc = curl_easy_escape(curl, query, 0);
            sds url = sdscatprintf(sdsempty(), "https://api.duckduckgo.com/?q=%s&format=json&no_html=1&skip_disambig=1", enc);
            curl_free(enc);
            curl_easy_cleanup(curl);
            long code = 0;
            sds body = http_get(url, "Accept: application/json", 20, &code);
            sdsfree(url);
            if (body && strncmp(body, "ERROR:", 6) != 0) {
                cJSON *root = cJSON_Parse(body);
                if (root) {
                    n = 0;
                    cJSON *abs = cJSON_GetObjectItem(root, "AbstractURL");
                    cJSON *heading = cJSON_GetObjectItem(root, "Heading");
                    if (abs && cJSON_IsString(abs) && abs->valuestring && abs->valuestring[0]) {
                        const char *ti = (heading && cJSON_IsString(heading) && heading->valuestring) ? heading->valuestring : abs->valuestring;
                        n = hit_add_unique(hits, n, maxn, abs->valuestring, ti);
                    }
                    cJSON *related = cJSON_GetObjectItem(root, "RelatedTopics");
                    if (related && cJSON_IsArray(related)) {
                        int m = cJSON_GetArraySize(related);
                        for (int i = 0; i < m && n < maxn; i++) {
                            cJSON *it = cJSON_GetArrayItem(related, i);
                            cJSON *fu = cJSON_GetObjectItem(it, "FirstURL");
                            cJSON *text = cJSON_GetObjectItem(it, "Text");
                            if (fu && cJSON_IsString(fu) && fu->valuestring)
                                n = hit_add_unique(hits, n, maxn, fu->valuestring,
                                    (text && cJSON_IsString(text) && text->valuestring) ? text->valuestring : fu->valuestring);
                            /* nested Topics */
                            cJSON *topics = cJSON_GetObjectItem(it, "Topics");
                            if (topics && cJSON_IsArray(topics)) {
                                int tm = cJSON_GetArraySize(topics);
                                for (int j = 0; j < tm && n < maxn; j++) {
                                    cJSON *t2 = cJSON_GetArrayItem(topics, j);
                                    cJSON *fu2 = cJSON_GetObjectItem(t2, "FirstURL");
                                    cJSON *tx2 = cJSON_GetObjectItem(t2, "Text");
                                    if (fu2 && cJSON_IsString(fu2) && fu2->valuestring)
                                        n = hit_add_unique(hits, n, maxn, fu2->valuestring,
                                            (tx2 && cJSON_IsString(tx2) && tx2->valuestring) ? tx2->valuestring : fu2->valuestring);
                                }
                            }
                        }
                    }
                    cJSON_Delete(root);
                    if (n > 0) {
                        sdsfree(body);
                        if (engine_out) *engine_out = "duckduckgo-instant";
                        return n;
                    }
                }
            }
            sdsfree(body);
        }
    }
    if (engine_out) *engine_out = "none";
    return 0;
}


sds web_search(const char *query, int max_results) {
    if (!query || !query[0]) return sdsnew("ERROR: empty query");
    if (max_results <= 0) max_results = 5;
    if (max_results > 10) max_results = 10;

    /* Keyless only — no Brave. */
    hit_t hits[10];
    memset(hits, 0, sizeof(hits));
    const char *engine = "none";
    int n = search_keyless(query, hits, max_results, &engine);
    if (n == 0) return sdsnew("ERROR: no search results (network or blocked; keyless engines empty)");

    sds out = sdscatprintf(sdsempty(), "=== web_search (%s) q=%s ===\n", engine, query);
    for (int i = 0; i < n; i++) {
        out = sdscatprintf(out, "%d. %s\n   URL: %s\n", i + 1, hits[i].title ? hits[i].title : "?",
                           hits[i].url ? hits[i].url : "?");
        if (hits[i].snippet && sdslen(hits[i].snippet) > 0)
            out = sdscatprintf(out, "   %s\n", hits[i].snippet);
        out = sdscat(out, "\n");
        hit_free(&hits[i]);
    }
    return out;
}

sds web_fetch(const char *url, size_t max_chars) {
    if (!url || !url[0]) return sdsnew("ERROR: empty url");
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0)
        return sdsnew("ERROR: only http(s) urls");
    /* Elo/OpenClaw web_fetch style: KEYLESS direct fetch + local readability-lite.
       No Brave. No Firecrawl required. */
    if (max_chars == 0) max_chars = (size_t)atoi(env_or("CWEB_MAX_CHARS", "50000"));
    if (max_chars < 500) max_chars = 500;
    if (max_chars > 200000) max_chars = 200000;

    long code = 0;
    sds raw = http_get(url, NULL, 30, &code);
    if (!raw) return sdsnew("ERROR: empty response");
    if (strncmp(raw, "ERROR:", 6) == 0) return raw;

    sds title = NULL;
    const char *extractor = "basic";
    sds md = html_to_markdown(raw, max_chars, &title, &extractor);
    /* Safety: if extract collapsed to almost nothing, fall back to plain stripped body */
    {
        int letters = 0;
        for (size_t i = 0; md && i < sdslen(md); i++) {
            char c = md[i];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) letters++;
        }
        if (letters < 80) {
            sds plain = strip_tags_decode(raw, sdslen(raw) > max_chars ? max_chars : sdslen(raw));
            if (plain && sdslen(plain) > (md ? sdslen(md) : 0) + 40) {
                sdsfree(md);
                md = plain;
                extractor = "fallback-text";
            } else {
                sdsfree(plain);
            }
        }
    }
    sdsfree(raw);

    const char *mode = env_or("CWEB_EXTRACT_MODE", "markdown"); /* markdown|text */
    sds body;
    if (strcasecmp(mode, "text") == 0) {
        body = html_to_text(md, max_chars); /* md already stripped-ish; re-plain */
        /* actually html_to_text expects html; for text mode convert md->plain here */
        sdsfree(body);
        body = sdsempty();
        for (size_t i = 0; i < sdslen(md); i++) {
            if (md[i] == '#' && (i == 0 || md[i-1] == '\n')) {
                while (i < sdslen(md) && (md[i] == '#' || md[i] == ' ')) i++;
                if (i < sdslen(md)) i--;
                continue;
            }
            if (md[i] == '[') {
                size_t j = i + 1;
                while (j < sdslen(md) && md[j] != ']') j++;
                if (j < sdslen(md) && j + 1 < sdslen(md) && md[j+1] == '(') {
                    body = sdscatlen(body, md + i + 1, j - i - 1);
                    size_t k = j + 2;
                    while (k < sdslen(md) && md[k] != ')') k++;
                    i = k;
                    continue;
                }
            }
            body = sdscatlen(body, md + i, 1);
        }
        sdsfree(md);
    } else {
        body = md;
        mode = "markdown";
    }

    sds out = sdscatprintf(sdsempty(),
        "=== web_fetch (elo-style, keyless) ===\n"
        "url: %s\n"
        "http: %ld\n"
        "title: %s\n"
        "extractor: %s\n"
        "extractMode: %s\n"
        "provider: direct+readability-lite\n\n"
        "%s\n",
        url, code,
        (title && sdslen(title)) ? title : "(none)",
        extractor ? extractor : "basic",
        mode,
        body);
    sdsfree(title);
    sdsfree(body);
    return out;
}

typedef struct {
    const char *url;
    size_t max_chars;
    sds result;
} fetch_job_t;

static void *fetch_worker(void *arg) {
    fetch_job_t *j = (fetch_job_t *)arg;
    j->result = web_fetch(j->url, j->max_chars);
    return NULL;
}

sds web_fetch_parallel(const char **urls, int n, size_t max_chars_each) {
    if (!urls || n <= 0) return sdsnew("ERROR: no urls");
    if (n > 8) n = 8;
    fetch_job_t jobs[8];
    pthread_t th[8];
    memset(jobs, 0, sizeof(jobs));

    for (int i = 0; i < n; i++) {
        jobs[i].url = urls[i];
        jobs[i].max_chars = max_chars_each;
        jobs[i].result = NULL;
        if (pthread_create(&th[i], NULL, fetch_worker, &jobs[i]) != 0) {
            jobs[i].result = sdsnew("ERROR: pthread_create failed");
            th[i] = (pthread_t)0;
        }
    }
    for (int i = 0; i < n; i++) {
        if (th[i]) pthread_join(th[i], NULL);
    }

    sds out = sdscatprintf(sdsempty(), "=== web_fetch_parallel n=%d ===\n", n);
    for (int i = 0; i < n; i++) {
        out = sdscatprintf(out, "\n######## COLUMN %d ########\n", i + 1);
        if (jobs[i].result) {
            out = sdscat(out, jobs[i].result);
            sdsfree(jobs[i].result);
        } else {
            out = sdscat(out, "ERROR: no result\n");
        }
    }
    return out;
}

sds web_browse(const char *query, int max_results, size_t max_chars_each) {
    if (!query || !query[0]) return sdsnew("ERROR: empty query");
    if (max_results <= 0) max_results = 4;
    if (max_results > 6) max_results = 6;
    if (max_chars_each == 0) max_chars_each = 4000;

    hit_t hits[10];
    memset(hits, 0, sizeof(hits));
    /* Keyless only — no Brave. */
    const char *engine = "none";
    int n = search_keyless(query, hits, max_results, &engine);
    if (n == 0) return sdsnew("ERROR: browse search returned 0 hits (keyless engines empty)");

    const char *urls[8];
    sds out = sdscatprintf(sdsempty(), "=== web_browse engine=%s q=%s ===\n# Search hits\n", engine, query);
    for (int i = 0; i < n; i++) {
        out = sdscatprintf(out, "%d. %s\n   %s\n", i + 1, hits[i].title ? hits[i].title : "?",
                           hits[i].url ? hits[i].url : "?");
        urls[i] = hits[i].url;
    }

    sds cols = web_fetch_parallel(urls, n, max_chars_each);
    out = sdscat(out, "\n# Parallel columns (fetched pages)\n");
    out = sdscatsds(out, cols);
    sdsfree(cols);

    for (int i = 0; i < n; i++) hit_free(&hits[i]);
    return out;
}

sds github_search(const char *query, int max_results) {
    if (!query || !query[0]) return sdsnew("ERROR: empty query");
    if (max_results <= 0) max_results = 5;
    if (max_results > 10) max_results = 10;

    CURL *curl = curl_easy_init();
    if (!curl) return sdsnew("ERROR: curl init failed");
    char *enc = curl_easy_escape(curl, query, 0);
    sds url = sdscatprintf(sdsempty(), "https://api.github.com/search/repositories?q=%s&per_page=%d", enc,
                           max_results);
    curl_free(enc);
    curl_easy_cleanup(curl);

    long code = 0;
    sds body = http_get(url, "Accept: application/vnd.github.v3+json", 30, &code);
    sdsfree(url);
    if (!body) return sdsnew("ERROR: empty github body");
    if (strncmp(body, "ERROR:", 6) == 0) return body;

    cJSON *json = cJSON_Parse(body);
    sdsfree(body);
    if (!json) return sdsnew("ERROR: github JSON parse");

    sds out = sdsnew("=== github_search ===\n");
    cJSON *items = cJSON_GetObjectItem(json, "items");
    if (items && cJSON_IsArray(items)) {
        int m = cJSON_GetArraySize(items);
        if (m == 0) out = sdscat(out, "No repositories found.\n");
        for (int i = 0; i < m && i < max_results; i++) {
            cJSON *item = cJSON_GetArrayItem(items, i);
            const char *full_name = cJSON_GetStringValue(cJSON_GetObjectItem(item, "full_name"));
            const char *html_url = cJSON_GetStringValue(cJSON_GetObjectItem(item, "html_url"));
            const char *desc = cJSON_GetStringValue(cJSON_GetObjectItem(item, "description"));
            int stars = 0;
            cJSON *st = cJSON_GetObjectItem(item, "stargazers_count");
            if (st && cJSON_IsNumber(st)) stars = st->valueint;
            out = sdscatprintf(out, "%d. %s (★ %d)\n   URL: %s\n   Desc: %s\n\n", i + 1,
                               full_name ? full_name : "?", stars, html_url ? html_url : "?",
                               desc ? desc : "");
        }
    } else {
        out = sdscat(out, "No items array.\n");
    }
    cJSON_Delete(json);
    return out;
}


/* ---------- web_job: host only calls this ---------- */


static int thin_body(const char *s) {
    if (!s) return 1;
    /* SPA / bot walls count as thin even if chrome text is long */
    if (strcasestr(s, "Uh oh!") || strcasestr(s, "There was an error while loading") ||
        strcasestr(s, "enable javascript") || strcasestr(s, "you need to enable") ||
        strcasestr(s, "Please enable Cookies") || strcasestr(s, "cf-browser-verification") ||
        strcasestr(s, "Just a moment...") || strcasestr(s, "Checking your browser"))
        return 1;
    /* count non-space alnum-ish */
    int n = 0;
    for (const char *p = s; *p; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')) n++;
        if (n > 400) return 0;
    }
    return 1;
}

/* GitHub repo root → README via API (keyless; avoids SPA "Uh oh" HTML) */
static sds fetch_github_readme(const char *url, size_t max_chars) {
    if (!url || !strstr(url, "github.com/")) return NULL;
    /* match https://github.com/owner/repo[/...] */
    const char *p = strstr(url, "github.com/");
    if (!p) return NULL;
    p += strlen("github.com/");
    char owner[128], repo[128];
    owner[0] = repo[0] = 0;
    if (sscanf(p, "%127[^/]/%127[^/#?]", owner, repo) != 2) return NULL;
    if (!owner[0] || !repo[0]) return NULL;
    /* skip non-repo paths that aren't repo root-ish */
    if (!strcmp(owner, "settings") || !strcmp(owner, "topics") || !strcmp(owner, "orgs")) return NULL;

    sds api = sdscatprintf(sdsempty(), "https://api.github.com/repos/%s/%s/readme", owner, repo);
    long code = 0;
    sds body = http_get(api, "Accept: application/vnd.github.raw", 25, &code);
    sdsfree(api);
    if (!body || strncmp(body, "ERROR:", 6) == 0 || thin_body(body) || code >= 400) {
        sdsfree(body);
        /* try raw main/master */
        const char *branches[] = {"main", "master", NULL};
        for (int b = 0; branches[b]; b++) {
            sds rawu = sdscatprintf(sdsempty(),
                "https://raw.githubusercontent.com/%s/%s/%s/README.md", owner, repo, branches[b]);
            body = http_get(rawu, NULL, 20, &code);
            sdsfree(rawu);
            if (body && strncmp(body, "ERROR:", 6) != 0 && !thin_body(body) && code < 400) break;
            sdsfree(body);
            body = NULL;
        }
    }
    if (!body) return NULL;
    size_t cap = max_chars ? max_chars : 12000;
    if (sdslen(body) > cap) sdsrange(body, 0, (ssize_t)cap - 1);
    sds out = sdscatprintf(sdsempty(),
        "=== web_fetch (github-readme fallback, keyless) ===\n"
        "url: %s\n"
        "http: %ld\n"
        "title: %s/%s README\n"
        "extractor: github-readme\n"
        "extractMode: markdown\n"
        "provider: api.github.com/readme\n\n"
        "%s\n",
        url, code, owner, repo, body);
    sdsfree(body);
    return out;
}

/* Optional keyless reader fallback for JS-heavy / thin pages */
static sds fetch_with_js_fallback(const char *url, size_t max_chars) {
    sds primary = web_fetch(url, max_chars);
    if (!primary) return sdsnew("ERROR: fetch failed");
    int need_fb = 0;
    if (strncmp(primary, "ERROR:", 6) == 0) need_fb = 1;
    else if (thin_body(primary)) need_fb = 1;
    else if (strcasestr(primary, "Uh oh!") || strcasestr(primary, "There was an error while loading") ||
             strcasestr(primary, "enable javascript") || strcasestr(primary, "you need to enable"))
        need_fb = 1;
    if (!need_fb) return primary;

    /* GitHub SPA HTML is often useless — prefer README API/raw first */
    if (strstr(url, "github.com/")) {
        sds gh = fetch_github_readme(url, max_chars);
        if (gh && !thin_body(gh) && strncmp(gh, "ERROR:", 6) != 0) {
            sdsfree(primary);
            return gh;
        }
        sdsfree(gh);
    }

    /* thin or error → try r.jina.ai (keyless reader, helps SPA-ish pages) */
    sds jurl = sdscatprintf(sdsempty(), "https://r.jina.ai/%s", url);
    long code = 0;
    sds raw = http_get(jurl, "Accept: text/plain", 35, &code);
    sdsfree(jurl);
    if (raw && strncmp(raw, "ERROR:", 6) != 0 && !thin_body(raw) && !strcasestr(raw, "AbuseAlleviationError")) {
        sds out = sdscatprintf(sdsempty(),
            "=== web_fetch (jina-reader fallback, keyless) ===\n"
            "url: %s\n"
            "http: %ld\n"
            "title: (reader)\n"
            "extractor: jina-reader\n"
            "extractMode: text\n"
            "provider: r.jina.ai\n\n",
            url, code);
        size_t cap = max_chars ? max_chars : 8000;
        if (sdslen(raw) > cap) sdsrange(raw, 0, (ssize_t)cap - 1);
        out = sdscatsds(out, raw);
        out = sdscat(out, "\n");
        sdsfree(raw);
        sdsfree(primary);
        return out;
    }
    sdsfree(raw);
    return primary;
}

typedef struct {
    const char *url;
    size_t max_chars;
    sds result;
} job_fetch_t;

static void *job_fetch_worker(void *arg) {
    job_fetch_t *j = (job_fetch_t *)arg;
    j->result = fetch_with_js_fallback(j->url, j->max_chars);
    return NULL;
}

typedef struct {
    char query[256];
    hit_t hits[8];
    int n;
    const char *engine;
} search_job_t;

static void *search_worker(void *arg) {
    search_job_t *j = (search_job_t *)arg;
    j->engine = "none";
    j->n = search_keyless(j->query, j->hits, 5, &j->engine);
    return NULL;
}

static sds extractive_snip(const char *col, size_t maxn) {
    if (!col) return sdsnew("");
    /* skip header lines until blank after provider */
    const char *p = strstr(col, "provider:");
    if (p) {
        p = strchr(p, '\n');
        if (p) p++;
        while (*p == '\n') p++;
    } else p = col;
    sds s = sdsnew(p);
    /* collapse spaces lightly already; trim length */
    if (sdslen(s) > maxn) sdsrange(s, 0, (ssize_t)maxn - 1);
    /* one-line-ish bullets: take first 3 non-empty lines */
    sds out = sdsempty();
    int lines = 0;
    size_t i = 0;
    while (i < sdslen(s) && lines < 4) {
        size_t j = i;
        while (j < sdslen(s) && s[j] != '\n') j++;
        size_t len = j - i;
        if (len > 20) {
            out = sdscat(out, "- ");
            out = sdscatlen(out, s + i, len > 220 ? 220 : len);
            out = sdscat(out, "\n");
            lines++;
        }
        i = (j < sdslen(s)) ? j + 1 : j;
    }
    sdsfree(s);
    return out;
}

sds web_job(const char *question, int max_results, size_t max_chars_each) {
    if (!question || !question[0]) return sdsnew("ERROR: empty question");
    if (max_results <= 0) max_results = 4;
    if (max_results > 6) max_results = 6;
    if (max_chars_each == 0) max_chars_each = 3500;

    /* Build 2-3 query variants for multi-search (parallel) */
    search_job_t sj[3];
    memset(sj, 0, sizeof(sj));
    snprintf(sj[0].query, sizeof(sj[0].query), "%s", question);
    /* variant 2: append docs/github bias if codeish */
    if (is_codeish(question))
        snprintf(sj[1].query, sizeof(sj[1].query), "%s docs OR github OR documentation", question);
    else
        snprintf(sj[1].query, sizeof(sj[1].query), "%s overview", question);
    /* variant 3: first 3 tokens */
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s", question);
        char *toks[6];
        int nt = 0;
        char *save = NULL;
        for (char *t = strtok_r(buf, " \t", &save); t && nt < 6; t = strtok_r(NULL, " \t", &save))
            toks[nt++] = t;
        if (nt >= 2) {
            sds q3 = sdsempty();
            for (int i = 0; i < nt && i < 3; i++) {
                if (i) q3 = sdscat(q3, " ");
                q3 = sdscat(q3, toks[i]);
            }
            snprintf(sj[2].query, sizeof(sj[2].query), "%s", q3);
            sdsfree(q3);
        } else {
            snprintf(sj[2].query, sizeof(sj[2].query), "%s", question);
        }
    }

    pthread_t sth[3];
    for (int i = 0; i < 3; i++) {
        if (pthread_create(&sth[i], NULL, search_worker, &sj[i]) != 0) {
            sj[i].n = search_keyless(sj[i].query, sj[i].hits, 5, &sj[i].engine);
            sth[i] = (pthread_t)0;
        }
    }
    for (int i = 0; i < 3; i++) if (sth[i]) pthread_join(sth[i], NULL);

    /* Merge URLs with simple score */
    typedef struct { sds url; sds title; int score; } cand_t;
    cand_t cands[24];
    int nc = 0;
    memset(cands, 0, sizeof(cands));
    for (int s = 0; s < 3; s++) {
        for (int i = 0; i < sj[s].n; i++) {
            if (!sj[s].hits[i].url) continue;
            int found = -1;
            for (int k = 0; k < nc; k++) {
                if (cands[k].url && strcmp(cands[k].url, sj[s].hits[i].url) == 0) {
                    found = k;
                    break;
                }
            }
            int add = 3 - i; /* higher for earlier ranks */
            if (sj[s].engine && strstr(sj[s].engine, "startpage")) add += 3;
            if (sj[s].engine && strstr(sj[s].engine, "known-docs")) add += 4;
            if (sj[s].engine && strstr(sj[s].engine, "duckduckgo")) add += 2;
            if (sj[s].engine && strstr(sj[s].engine, "wikipedia")) add -= 1;
            if (found >= 0) {
                cands[found].score += add + 2; /* multi-query agreement */
            } else if (nc < 24) {
                cands[nc].url = sdsdup(sj[s].hits[i].url);
                cands[nc].title = sj[s].hits[i].title ? sdsdup(sj[s].hits[i].title) : sdsnew("");
                cands[nc].score = add;
                nc++;
            }
        }
    }
    
    /* token overlap boost against question (reduces random wiki near-matches) */
    {
        char qbuf[256];
        snprintf(qbuf, sizeof(qbuf), "%s", question);
        for (char *c = qbuf; *c; c++) if (*c >= 'A' && *c <= 'Z') *c = (char)(*c - 'A' + 'a');
        char *toks[12];
        int nt = 0;
        char *save = NULL;
        for (char *tk = strtok_r(qbuf, " \t", &save); tk && nt < 12; tk = strtok_r(NULL, " \t", &save)) {
            if (strlen(tk) >= 3) toks[nt++] = tk;
        }
        for (int i = 0; i < nc; i++) {
            char hay[512];
            snprintf(hay, sizeof(hay), "%s %s", cands[i].title ? cands[i].title : "", cands[i].url ? cands[i].url : "");
            for (char *c = hay; *c; c++) if (*c >= 'A' && *c <= 'Z') *c = (char)(*c - 'A' + 'a');
            int hits = 0;
            for (int t = 0; t < nt; t++) if (strstr(hay, toks[t])) hits++;
            cands[i].score += hits * 3;
            if (strstr(hay, "openclipart") || strstr(hay, "opencl.org") || strstr(hay, "khronos") ||
                strstr(hay, "liberland") || strstr(hay, "liburnians") ||
                strstr(hay, "redistribution") || strstr(hay, "squirrel") || strstr(hay, "chris squire") ||
                strstr(hay, "ohmyzsh") || strstr(hay, "nocode") || strstr(hay, "best-websites-a-programmer"))
                cands[i].score -= 12;
            if (strstr(hay, "github.com") || strstr(hay, "docs.") || strstr(hay, "kubernetes.io") ||
                strstr(hay, "curl.se") || strstr(hay, "mdn.mozilla") || strstr(hay, "webpack.js.org") ||
                strstr(hay, "iana.org") || strstr(hay, "python-requests.org") || strstr(hay, "tokio.rs") ||
                strstr(hay, "fastapi.tiangolo") || strstr(hay, "docs.openclaw") ||
                strstr(hay, "redis.io") || strstr(hay, "react.dev") || strstr(hay, "sqlite.org") ||
                strstr(hay, "nodejs.org") || strstr(hay, "typescriptlang.org") || strstr(hay, "go.dev") ||
                strstr(hay, "nginx.org") || strstr(hay, "jwt.io") || strstr(hay, "oauth.net") ||
                strstr(hay, "gov.pl") || strstr(hay, "schillerstadt-marbach") ||
                strstr(hay, "tripadvisor.com"))
                cands[i].score += 5;
            if (strstr(hay, "yelp.com") || strstr(hay, "m.yelp.") || strstr(hay, "instagram.com") ||
                strstr(hay, "facebook.com") || strstr(hay, "linkedin.com"))
                cands[i].score -= 6;
            /* Prefer docs over monorepo roots when question is conceptual */
            if ((strcasestr(question, "what is") || strcasestr(question, "ingress") || strcasestr(question, "tutorial")) &&
                (strstr(hay, "/docs/") || strstr(hay, "concepts/") || strstr(hay, "guides/")))
                cands[i].score += 4;
            if (strstr(hay, "github.com/") && strstr(hay, "/kubernetes/kubernetes"))
                cands[i].score -= 2; /* monorepo root often SPA noise for concept Qs */
        }
    }

/* sort by score desc (simple insertion) */
    for (int i = 1; i < nc; i++) {
        cand_t key = cands[i];
        int j = i - 1;
        while (j >= 0 && cands[j].score < key.score) {
            cands[j + 1] = cands[j];
            j--;
        }
        cands[j + 1] = key;
    }

    
    /* Prefer GitHub repos for code-ish questions (fixes OpenClaw→OpenCL wiki junk). */
    sds gh = NULL;
    /* Seed known docs into ranked candidates with high score */
    {
        hit_t seeds[8];
        memset(seeds, 0, sizeof(seeds));
        int sn = seed_known_docs(question, seeds, 0, 8);
        for (int i = 0; i < sn && nc < 24; i++) {
            int found = -1;
            for (int k = 0; k < nc; k++) {
                if (cands[k].url && seeds[i].url && strcmp(cands[k].url, seeds[i].url) == 0) {
                    found = k; break;
                }
            }
            if (found >= 0) {
                cands[found].score += 20;
            } else {
                cands[nc].url = sdsdup(seeds[i].url);
                cands[nc].title = seeds[i].title ? sdsdup(seeds[i].title) : sdsnew("");
                cands[nc].score = 28;
                nc++;
            }
            hit_free(&seeds[i]);
        }
        for (int i = 1; i < nc; i++) {
            cand_t key = cands[i];
            int j = i - 1;
            while (j >= 0 && cands[j].score < key.score) {
                cands[j + 1] = cands[j];
                j--;
            }
            cands[j + 1] = key;
        }
    }

    if (is_codeish(question)) {
        {
            /* Prefer product token queries so OpenClaw ≠ random MCP repos */
            char gbuf[128];
            github_query_simplify(question, gbuf, sizeof(gbuf));
            const char *gq = gbuf[0] ? gbuf : question;
            gh = github_search(gq, 5);
        }
        if (gh && strncmp(gh, "ERROR:", 6) != 0) {
            const char *gp = gh;
            while ((gp = strstr(gp, "URL: ")) != NULL && nc < 24) {
                gp += 5;
                const char *ge = strchr(gp, '\n');
                if (!ge) break;
                sds u = sdsnewlen(gp, (size_t)(ge - gp));
                while (sdslen(u) && (u[sdslen(u)-1]=='\r' || u[sdslen(u)-1]==' ' || u[sdslen(u)-1]=='\t'))
                    sdsrange(u, 0, (ssize_t)sdslen(u) - 2);
                if (strncmp(u, "http", 4) == 0) {
                    int found = -1;
                    for (int k = 0; k < nc; k++) {
                        if (cands[k].url && strcmp(cands[k].url, u) == 0) { found = k; break; }
                    }
                    if (found >= 0) {
                        cands[found].score += 10;
                        sdsfree(u);
                    } else {
                        cands[nc].url = u;
                        {
                            const char *slash = strrchr(cands[nc].url, '/');
                            cands[nc].title = sdsnew(slash ? slash + 1 : cands[nc].url);
                        }
                        cands[nc].score = 14;
                        nc++;
                    }
                } else {
                    sdsfree(u);
                }
                gp = ge + 1;
            }
            /* re-sort so github injects can rise above wiki junk */
            for (int i = 1; i < nc; i++) {
                cand_t key = cands[i];
                int j = i - 1;
                while (j >= 0 && cands[j].score < key.score) {
                    cands[j + 1] = cands[j];
                    j--;
                }
                cands[j + 1] = key;
            }
        }
    }

    int take = max_results < nc ? max_results : nc;
    const char *urls[8];
    for (int i = 0; i < take; i++) urls[i] = cands[i].url;

    /* parallel fetch with JS-thin fallback (gh may already be filled for code-ish) */
    job_fetch_t jobs[8];
    pthread_t th[8];
    memset(jobs, 0, sizeof(jobs));
    for (int i = 0; i < take; i++) {
        jobs[i].url = urls[i];
        jobs[i].max_chars = max_chars_each;
        if (pthread_create(&th[i], NULL, job_fetch_worker, &jobs[i]) != 0) {
            jobs[i].result = fetch_with_js_fallback(urls[i], max_chars_each);
            th[i] = (pthread_t)0;
        }
    }
    for (int i = 0; i < take; i++) if (th[i]) pthread_join(th[i], NULL);

    /* If a top fetch is 403/ERROR/JS-wall, swap in next unused candidate once */
    {
        int used[24];
        memset(used, 0, sizeof(used));
        for (int i = 0; i < take; i++) used[i] = 1;
        int next = take;
        for (int i = 0; i < take; i++) {
            const char *r = jobs[i].result ? jobs[i].result : "";
            int bad = (!r[0]) || strncmp(r, "ERROR:", 6) == 0 ||
                      strstr(r, "Please enable JS") ||
                      (strstr(r, "HTTP 403") != NULL);
            if (!bad) continue;
            while (next < nc) {
                if (used[next]) { next++; continue; }
                used[next] = 1;
                sds alt = fetch_with_js_fallback(cands[next].url, max_chars_each);
                const char *ar = alt ? alt : "";
                int alt_bad = (!ar[0]) || strncmp(ar, "ERROR:", 6) == 0 ||
                              strstr(ar, "Please enable JS") || strstr(ar, "HTTP 403");
                if (!alt_bad) {
                    sdsfree(jobs[i].result);
                    jobs[i].result = alt;
                    sdsfree(cands[i].url);
                    sdsfree(cands[i].title);
                    cands[i].url = sdsdup(cands[next].url);
                    cands[i].title = cands[next].title ? sdsdup(cands[next].title) : sdsnew("");
                    cands[i].score = cands[next].score;
                    urls[i] = cands[i].url;
                    jobs[i].url = urls[i];
                    next++;
                    break;
                }
                sdsfree(alt);
                next++;
            }
        }
    }

    sds out = sdscatprintf(sdsempty(),
        "=== web_job (keyless, multi-search + parallel columns) ===\n"
        "question: %s\n"
        "policy: host model should NOT search; this job already did multi-search + parallel fetch\n"
        "queries:\n"
        "  1) %s [%s, %d hits]\n"
        "  2) %s [%s, %d hits]\n"
        "  3) %s [%s, %d hits]\n"
        "merged_unique_urls: %d  fetching_top: %d\n\n"
        "# Ranked sources\n",
        question,
        sj[0].query, sj[0].engine ? sj[0].engine : "?", sj[0].n,
        sj[1].query, sj[1].engine ? sj[1].engine : "?", sj[1].n,
        sj[2].query, sj[2].engine ? sj[2].engine : "?", sj[2].n,
        nc, take);

    for (int i = 0; i < take; i++) {
        out = sdscatprintf(out, "%d. (score %d) %s\n   %s\n", i + 1, cands[i].score,
                           cands[i].title ? cands[i].title : "?",
                           cands[i].url ? cands[i].url : "?");
    }

    out = sdscat(out, "\n# Parallel columns\n");
    for (int i = 0; i < take; i++) {
        out = sdscatprintf(out, "\n######## COLUMN %d ########\n", i + 1);
        if (jobs[i].result) out = sdscatsds(out, jobs[i].result);
        else out = sdscat(out, "ERROR: no result\n");
    }

    if (gh) {
        out = sdscat(out, "\n######## COLUMN github ########\n");
        out = sdscatsds(out, gh);
    }

    /* extractive answer pack for host model */
    out = sdscat(out, "\n# Answer pack (extractive — host should synthesize, not re-search)\n");
    out = sdscatprintf(out, "question: %s\n", question);
    if (take == 0) {
        out = sdscat(out, "status: NO_SOURCES — engines empty or blocked; try sharper query\n");
    } else {
        out = sdscat(out, "status: OK\nfindings:\n");
        for (int i = 0; i < take; i++) {
            out = sdscatprintf(out, "\n## Source %d: %s\nURL: %s\n", i + 1,
                               cands[i].title ? cands[i].title : "?",
                               cands[i].url ? cands[i].url : "?");
            sds sn = extractive_snip(jobs[i].result, 1200);
            out = sdscatsds(out, sn);
            sdsfree(sn);
        }
    }
    out = sdscat(out,
        "\n# Host instruction\n"
        "You already have multi-search + parallel page text above.\n"
        "Write the final answer from this pack only. Do not call web_search again unless status is NO_SOURCES.\n");

    for (int i = 0; i < take; i++) sdsfree(jobs[i].result);
    for (int i = 0; i < nc; i++) {
        sdsfree(cands[i].url);
        sdsfree(cands[i].title);
    }
    for (int s = 0; s < 3; s++)
        for (int i = 0; i < sj[s].n; i++) hit_free(&sj[s].hits[i]);
    sdsfree(gh);
    return out;
}
