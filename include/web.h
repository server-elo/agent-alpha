#pragma once

#include "../deps/cJSON.h"
#include "../deps/sds.h"

/* HTTP helpers (libcurl) */
sds http_get(const char *url, const char *extra_header, long timeout_s, long *http_code_out);
sds html_to_text(const char *html, size_t max_chars);

/* Tools */
sds web_search(const char *query, int max_results);
sds web_fetch(const char *url, size_t max_chars);
sds web_browse(const char *query, int max_results, size_t max_chars_each);
sds github_search(const char *query, int max_results);

/* Parallel column pack: fetch multiple URLs concurrently */
sds web_fetch_parallel(const char **urls, int n, size_t max_chars_each);

/* One-shot research job: multi-search + parallel fetch + extractive pack.
   Host model only calls this — does not need to search itself. */
sds web_job(const char *question, int max_results, size_t max_chars_each);
