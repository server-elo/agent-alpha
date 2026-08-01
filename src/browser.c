#include "alpha.h"
#include <curl/curl.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdint.h>
#include <signal.h>

/*
 * Pure-C browser (CDP-based).
 * ONE sticky tab: open/navigate reuses Page.navigate.
 * Interact: click | type | snapshot | eval | press on sticky tab.
 *
 * CDP: ALPHA_CDP_URL or http://127.0.0.1:18800
 * Sticky: /tmp/agent-alpha-browser-tab.id
 * ALPHA_BROWSER_VISIBLE=1 also runs macOS open
 */

#ifndef ALPHA_DEFAULT_CDP
#define ALPHA_DEFAULT_CDP "http://127.0.0.1:18800"
#endif
#define STICKY_TAB_PATH "/tmp/agent-alpha-browser-tab.id"

typedef struct { sds body; } curl_acc_t;

static size_t acc_write(char *ptr, size_t size, size_t nmemb, void *userdata) {
    curl_acc_t *a = userdata;
    size_t n = size * nmemb;
    a->body = sdscatlen(a->body, ptr, n);
    return n;
}

static const char *cdp_base(void) {
    const char *e = getenv("ALPHA_CDP_URL");
    return (e && e[0]) ? e : ALPHA_DEFAULT_CDP;
}
static const char *browser_app(void) {
    const char *e = getenv("ALPHA_BROWSER_APP");
    return (e && e[0]) ? e : "Google Chrome";
}
static int want_visible_open(void) {
    const char *e = getenv("ALPHA_BROWSER_VISIBLE");
    return e && e[0] == '1';
}

static long cdp_http(const char *method, const char *url, sds *out_body) {
    if (out_body) *out_body = sdsempty();
    CURL *curl = curl_easy_init();
    if (!curl) return 0;
    curl_acc_t acc = { .body = sdsempty() };
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, acc_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &acc);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 8L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if (method && strcmp(method, "GET") != 0)
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    CURLcode rc = curl_easy_perform(curl);
    long http = 0;
    if (rc == CURLE_OK) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK) {
        sdsfree(acc.body);
        if (out_body)
            *out_body = sdscatprintf(sdsempty(), "ERROR curl: %s", curl_easy_strerror(rc));
        return 0;
    }
    if (out_body) *out_body = acc.body;
    else sdsfree(acc.body);
    return http;
}

static int cdp_alive(void) {
    sds body = NULL;
    char url[512];
    snprintf(url, sizeof(url), "%s/json/version", cdp_base());
    long http = cdp_http("GET", url, &body);
    int ok = (http == 200 && body && body[0] == '{');
    if (body) sdsfree(body);
    return ok;
}

static void sticky_save(const char *tab_id) {
    if (!tab_id || !tab_id[0]) return;
    FILE *f = fopen(STICKY_TAB_PATH, "w");
    if (!f) return;
    fprintf(f, "%s\n", tab_id);
    fclose(f);
}

static sds sticky_load(void) {
    FILE *f = fopen(STICKY_TAB_PATH, "r");
    if (!f) return NULL;
    char buf[128];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return NULL; }
    fclose(f);
    size_t n = strlen(buf);
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = 0;
    return n ? sdsnew(buf) : NULL;
}

static sds url_encode_query(const char *url) {
    sds enc = sdsempty();
    for (const unsigned char *p = (const unsigned char *)url; *p; p++) {
        if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
            (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.' ||
            *p == '~' || *p == '/' || *p == ':' || *p == '?' || *p == '=' ||
            *p == '&' || *p == '%' || *p == '#' || *p == '+')
            enc = sdscatlen(enc, (const char *)p, 1);
        else
            enc = sdscatprintf(enc, "%%%02X", *p);
    }
    return enc;
}

static cJSON *cdp_find_tab(const char *tab_id) {
    if (!tab_id || !tab_id[0]) return NULL;
    char url[512];
    snprintf(url, sizeof(url), "%s/json", cdp_base());
    sds body = NULL;
    if (cdp_http("GET", url, &body) != 200 || !body) {
        if (body) sdsfree(body);
        return NULL;
    }
    cJSON *arr = cJSON_Parse(body);
    sdsfree(body);
    if (!arr || !cJSON_IsArray(arr)) { if (arr) cJSON_Delete(arr); return NULL; }
    cJSON *found = NULL;
    int n = cJSON_GetArraySize(arr);
    for (int i = 0; i < n; i++) {
        cJSON *t = cJSON_GetArrayItem(arr, i);
        const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(t, "id"));
        const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(t, "type"));
        if (!id || strcmp(id, tab_id) != 0) continue;
        if (type && strcmp(type, "page") != 0 && strcmp(type, "webview") != 0) continue;
        found = cJSON_Duplicate(t, 1);
        break;
    }
    cJSON_Delete(arr);
    return found;
}

static cJSON *cdp_first_page_tab(void) {
    char url[512];
    snprintf(url, sizeof(url), "%s/json", cdp_base());
    sds body = NULL;
    if (cdp_http("GET", url, &body) != 200 || !body) {
        if (body) sdsfree(body);
        return NULL;
    }
    cJSON *arr = cJSON_Parse(body);
    sdsfree(body);
    if (!arr || !cJSON_IsArray(arr)) { if (arr) cJSON_Delete(arr); return NULL; }
    cJSON *pick = NULL, *blank = NULL;
    int n = cJSON_GetArraySize(arr);
    for (int i = 0; i < n; i++) {
        cJSON *t = cJSON_GetArrayItem(arr, i);
        const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(t, "type"));
        const char *tu = cJSON_GetStringValue(cJSON_GetObjectItem(t, "url"));
        if (type && strcmp(type, "page") != 0) continue;
        if (!pick) pick = t;
        if (tu && (strstr(tu, "chrome://newtab") || strcmp(tu, "about:blank") == 0 ||
                   strstr(tu, "chrome://new-tab"))) {
            blank = t;
            break;
        }
    }
    cJSON *out = cJSON_Duplicate(blank ? blank : pick, 1);
    cJSON_Delete(arr);
    return out;
}

static void cdp_activate(const char *tab_id) {
    if (!tab_id) return;
    char url[640];
    snprintf(url, sizeof(url), "%s/json/activate/%s", cdp_base(), tab_id);
    sds body = NULL;
    cdp_http("GET", url, &body);
    if (body) sdsfree(body);
}

static sds cdp_ws_call_id(const char *ws_url, const char *json_msg, int expect_id) {
    if (!ws_url || strncmp(ws_url, "ws://", 5) != 0)
        return sdsnew("ERROR: need ws:// debugger URL");
    char host[256] = {0}, path[1024] = {0};
    int port = 80;
    const char *p = ws_url + 5;
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    if (!slash) return sdsnew("ERROR: bad ws url path");
    size_t hostlen;
    if (colon && colon < slash) { hostlen = (size_t)(colon - p); port = atoi(colon + 1); }
    else hostlen = (size_t)(slash - p);
    if (hostlen >= sizeof(host)) hostlen = sizeof(host) - 1;
    memcpy(host, p, hostlen); host[hostlen] = 0;
    snprintf(path, sizeof(path), "%s", slash);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    char port_s[16]; snprintf(port_s, sizeof(port_s), "%d", port);
    if (getaddrinfo(host, port_s, &hints, &res) != 0 || !res)
        return sdsnew("ERROR: getaddrinfo ws");
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return sdsnew("ERROR: connect ws");

    struct timeval tv = { .tv_sec = 6, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    char req[2048];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
             path, host, port);
    if (send(fd, req, strlen(req), 0) < 0) { close(fd); return sdsnew("ERROR: ws handshake send"); }
    char hbuf[8192];
    ssize_t hr = recv(fd, hbuf, sizeof(hbuf) - 1, 0);
    if (hr <= 0) { close(fd); return sdsnew("ERROR: ws handshake recv"); }
    hbuf[hr] = 0;
    if (!strstr(hbuf, "101")) { close(fd); return sdscatprintf(sdsempty(), "ERROR: ws upgrade failed: %.200s", hbuf); }

    size_t plen = strlen(json_msg);
    unsigned char mask[4] = {0x12, 0x34, 0x56, 0x78};
    unsigned char hdr[14]; size_t hlen = 0;
    hdr[0] = 0x81;
    if (plen < 126) { hdr[1] = 0x80 | (unsigned char)plen; hlen = 2; }
    else if (plen <= 0xffff) {
        hdr[1] = 0x80 | 126; hdr[2] = (unsigned char)((plen >> 8) & 0xff);
        hdr[3] = (unsigned char)(plen & 0xff); hlen = 4;
    } else { close(fd); return sdsnew("ERROR: payload too large"); }
    memcpy(hdr + hlen, mask, 4); hlen += 4;
    size_t flen = hlen + plen;
    unsigned char *frame = malloc(flen);
    if (!frame) { close(fd); return sdsnew("ERROR: oom"); }
    memcpy(frame, hdr, hlen);
    for (size_t i = 0; i < plen; i++) frame[hlen + i] = (unsigned char)json_msg[i] ^ mask[i % 4];
    if (send(fd, frame, flen, 0) < 0) { free(frame); close(fd); return sdsnew("ERROR: ws send"); }
    free(frame);

    /* Reassembly, because a CDP reply is not always one frame.
     *
     * Two ways this loop used to return corrupt JSON as if it were a result:
     * a fragmented message (FIN=0 followed by continuation frames) had only its
     * first fragment returned, and a payload cut short by the recv timeout was
     * returned truncated. Both parse as garbage downstream -- the caller sees a
     * half snapshot, not an error. So: join fragments until FIN, and treat a
     * short read as a failure rather than a result. */
    sds best = NULL;
    sds msg_buf = NULL;      /* fragments of the message being assembled */
    const char *fail = NULL;
    for (int attempt = 0; attempt < 12; attempt++) {
        unsigned char rh[2];
        if (recv(fd, rh, 2, MSG_WAITALL) != 2) break;
        int fin = (rh[0] & 0x80) != 0;
        int opcode = rh[0] & 0x0f;
        int masked = (rh[1] & 0x80) != 0;
        uint64_t rlen = rh[1] & 0x7f;
        if (rlen == 126) {
            unsigned char e[2];
            if (recv(fd, e, 2, MSG_WAITALL) != 2) break;
            rlen = ((uint64_t)e[0] << 8) | e[1];
        } else if (rlen == 127) {
            unsigned char e[8];
            if (recv(fd, e, 8, MSG_WAITALL) != 8) break;
            rlen = 0; for (int i = 0; i < 8; i++) rlen = (rlen << 8) | e[i];
        }
        unsigned char rmask[4] = {0};
        if (masked && recv(fd, rmask, 4, MSG_WAITALL) != 4) break;
        if (rlen > ALPHA_WS_MAX_FRAME) { fail = "ERROR: ws frame too large"; break; }
        char *payload = malloc((size_t)rlen + 1);
        if (!payload) { fail = "ERROR: oom"; break; }
        size_t got = 0;
        int short_read = 0;
        while (got < rlen) {
            ssize_t n = recv(fd, payload + got, (size_t)rlen - got, 0);
            if (n <= 0) { short_read = 1; break; }
            got += (size_t)n;
        }
        if (short_read) { free(payload); fail = "ERROR: ws message truncated"; break; }
        payload[got] = 0;
        if (masked) for (size_t i = 0; i < got; i++) payload[i] ^= rmask[i % 4];

        if (opcode == 0x8) { free(payload); break; }            /* close */
        if (opcode == 0x9 || opcode == 0xa) { free(payload); continue; }  /* ping/pong */
        if (opcode != 0x0 && opcode != 0x1 && opcode != 0x2) { free(payload); continue; }

        if (opcode != 0x0) {                                    /* first frame */
            if (msg_buf) sdsfree(msg_buf);
            msg_buf = sdsempty();
        } else if (!msg_buf) {                                  /* stray continuation */
            free(payload);
            continue;
        }
        if (sdslen(msg_buf) + got > ALPHA_WS_MAX_MESSAGE) {
            free(payload);
            fail = "ERROR: ws message too large";
            break;
        }
        msg_buf = sdscatlen(msg_buf, payload, got);
        free(payload);
        if (!fin) continue;                                     /* more to come */

        cJSON *j = cJSON_Parse(msg_buf);
        if (j) {
            cJSON *id = cJSON_GetObjectItem(j, "id");
            int match = (expect_id <= 0) || (cJSON_IsNumber(id) && id->valueint == expect_id);
            cJSON_Delete(j);
            if (match) {
                if (best) sdsfree(best);
                best = msg_buf; msg_buf = NULL;
                break;
            }
        }
        /* Not the reply we asked for (an unsolicited CDP event, say): keep the
         * first one only as a last resort. */
        if (!best) best = sdsdup(msg_buf);
    }
    if (msg_buf) sdsfree(msg_buf);
    close(fd);
    /* A failure wins over a partial or unrelated message: reporting the error
     * is the whole point, and returning stale data instead would put the caller
     * back where it was -- acting on something that is not the reply. */
    if (fail) { if (best) sdsfree(best); return sdsnew(fail); }
    return best ? best : sdsnew("ERROR: ws no response");
}

static sds cdp_ws_call(const char *ws_url, const char *json_msg) {
    int eid = 0;
    cJSON *tmp = cJSON_Parse(json_msg);
    if (tmp) {
        cJSON *id = cJSON_GetObjectItem(tmp, "id");
        if (cJSON_IsNumber(id)) eid = id->valueint;
        cJSON_Delete(tmp);
    }
    return cdp_ws_call_id(ws_url, json_msg, eid);
}

static sds cdp_page_navigate(const char *ws_url, const char *url) {
    sds enable = sdsnew("{\"id\":1,\"method\":\"Page.enable\",\"params\":{}}");
    sds r1 = cdp_ws_call(ws_url, enable);
    sdsfree(enable);
    if (r1 && strncmp(r1, "ERROR", 5) == 0) return r1;
    if (r1) sdsfree(r1);
    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "url", url);
    char *ps = cJSON_PrintUnformatted(params);
    cJSON_Delete(params);
    sds msg = sdscatprintf(sdsempty(), "{\"id\":2,\"method\":\"Page.navigate\",\"params\":%s}", ps ? ps : "{}");
    free(ps);
    sds r2 = cdp_ws_call(ws_url, msg);
    sdsfree(msg);
    return r2;
}

static sds cdp_eval_js(const char *ws_url, const char *expression) {
    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "expression", expression ? expression : "null");
    cJSON_AddBoolToObject(params, "returnByValue", 1);
    cJSON_AddBoolToObject(params, "awaitPromise", 1);
    char *ps = cJSON_PrintUnformatted(params);
    cJSON_Delete(params);
    sds msg = sdscatprintf(sdsempty(), "{\"id\":10,\"method\":\"Runtime.evaluate\",\"params\":%s}", ps ? ps : "{}");
    free(ps);
    sds r = cdp_ws_call(ws_url, msg);
    sdsfree(msg);
    return r;
}

static sds json_get_eval_value(sds cdp_json) {
    if (!cdp_json) return sdsnew("");
    cJSON *root = cJSON_Parse(cdp_json);
    if (!root) return sdsnew(cdp_json);
    cJSON *result = cJSON_GetObjectItem(root, "result");
    cJSON *inner = result ? cJSON_GetObjectItem(result, "result") : NULL;
    cJSON *val = inner ? cJSON_GetObjectItem(inner, "value") : NULL;
    cJSON *exc = result ? cJSON_GetObjectItem(result, "exceptionDetails") : NULL;
    sds out = sdsempty();
    if (exc) {
        char *es = cJSON_PrintUnformatted(exc);
        out = sdscatprintf(out, "EXCEPTION %s", es ? es : "");
        free(es);
    } else if (val) {
        if (cJSON_IsString(val)) out = sdscat(out, val->valuestring ? val->valuestring : "");
        else {
            char *vs = cJSON_PrintUnformatted(val);
            out = sdscat(out, vs ? vs : "");
            free(vs);
        }
    } else {
        char *raw = cJSON_PrintUnformatted(root);
        out = sdscat(out, raw ? raw : "");
        free(raw);
    }
    cJSON_Delete(root);
    return out;
}

static sds js_escape(const char *s) {
    sds o = sdsempty();
    if (!s) return o;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '\\' || *p == '\'' ) o = sdscatprintf(o, "\\%c", *p);
        else if (*p == '\n') o = sdscat(o, "\\n");
        else if (*p == '\r') o = sdscat(o, "\\r");
        else if (*p < 0x20) o = sdscatprintf(o, "\\u%04x", *p);
        else o = sdscatlen(o, (const char *)p, 1);
    }
    return o;
}

/* `open -a App URL` is macOS-only; elsewhere the equivalent is xdg-open, which
 * takes no app argument and picks the desktop's default handler. Returning the
 * argv here keeps the fork/exec below identical on both. */
static int opener_argv(const char *app, const char *url, const char *argv[5]) {
#if defined(__APPLE__) && !defined(ALPHA_FORCE_XDG_OPEN)
    argv[0] = "/usr/bin/open"; argv[1] = "open"; argv[2] = "-a";
    argv[3] = app; argv[4] = url;
    return 5;
#else
    (void)app;
    static const char *candidates[] = { "/usr/bin/xdg-open", "/bin/xdg-open" };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (access(candidates[i], X_OK) != 0) continue;
        argv[0] = candidates[i]; argv[1] = "xdg-open"; argv[2] = url;
        return 3;
    }
    return 0;
#endif
}

static sds open_in_browser_app(const char *url) {
    if (!url || !url[0]) return sdsnew("ERROR: url required");
    const char *app = browser_app();

    const char *av[5] = { 0 };
    int an = opener_argv(app, url, av);
    if (an == 0)
        return sdsnew("ERROR: no xdg-open on this system; set ALPHA_CDP_URL and "
                      "drive the browser over CDP instead.");

    /* exec `open` directly: no shell, no temp script, so the app name and URL
     * can never be interpreted as shell syntax. Own process group + real kill
     * on timeout, so a hung/backgrounded child cannot outlive the 15s cap. */
    char outf[] = "/tmp/alpha-browser-out-XXXXXX";
    int ofd = mkstemp(outf);
    if (ofd < 0) return sdsnew("ERROR mkstemp out");

    int timed_out = 0;
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        dup2(ofd, STDOUT_FILENO);
        dup2(ofd, STDERR_FILENO);
        close(ofd);
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, STDIN_FILENO); close(devnull); }
        if (an == 3) execl(av[0], av[1], av[2], (char *)NULL);
        else         execl(av[0], av[1], av[2], av[3], av[4], (char *)NULL);
        _exit(127);
    }
    if (pid < 0) {
        close(ofd);
        unlink(outf);
        return sdsnew("ERROR fork");
    }
    close(ofd);

    int status = 0;
    for (int waited = 0; waited < 150; waited++) {   /* 150 * 100ms = 15s */
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) goto reaped;
        if (r < 0) break;
        usleep(100000);
    }
    timed_out = 1;
    kill(-pid, SIGKILL);
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
reaped:
    ;
    FILE *f = fopen(outf, "rb");
    sds out = sdsempty();
    if (f) { char buf[4096]; size_t n; while ((n = fread(buf, 1, sizeof(buf), f)) > 0) out = sdscatlen(out, buf, n); fclose(f); }
    unlink(outf);
    int ec = (!timed_out && WIFEXITED(status)) ? WEXITSTATUS(status) : -1;
    sds res = sdscatprintf(sdsempty(),
                           "ACTION=open_app\nAPP=%s\nURL=%s\n__OPEN_EXIT:%d%s\nPROOF:\n%s\n",
                           an == 3 ? "(system default)" : app, url, ec,
                           timed_out ? " (TIMEOUT after 15s — process group killed)" : "",
                           out && out[0] ? out : "(no output)");
    sdsfree(out);
    return res;
}

static cJSON *cdp_create_tab(const char *url) {
    sds enc = url_encode_query(url && url[0] ? url : "about:blank");
    char endpoint[PATH_MAX * 4 + 64];
    snprintf(endpoint, sizeof(endpoint), "%s/json/new?%s", cdp_base(), enc);
    sdsfree(enc);
    sds body = NULL;
    long http = cdp_http("PUT", endpoint, &body);
    if (http == 0 || http >= 400) {
        if (body) sdsfree(body);
        http = cdp_http("GET", endpoint, &body);
    }
    if (http < 200 || http >= 300 || !body || body[0] != '{') {
        if (body) sdsfree(body);
        return NULL;
    }
    cJSON *tab = cJSON_Parse(body);
    sdsfree(body);
    return tab;
}

static sds cdp_goto_one_tab(const char *url, int force_new) {
    if (!url || !url[0]) return sdsnew("ERROR: url required");
    cJSON *tab = NULL;
    const char *mode = "navigate_sticky";
    if (!force_new) {
        sds sid = sticky_load();
        if (sid) { tab = cdp_find_tab(sid); if (!tab) mode = "sticky_missing"; sdsfree(sid); }
        if (!tab) { tab = cdp_first_page_tab(); if (tab) mode = "reuse_existing_page"; }
    }
    if (!tab || force_new) {
        if (tab) { cJSON_Delete(tab); tab = NULL; }
        tab = cdp_create_tab(url);
        mode = force_new ? "new_tab" : "create_first_sticky";
        if (!tab) return sdsnew("ERROR: could not create CDP tab");
        const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(tab, "id"));
        sticky_save(id); cdp_activate(id);
        sds res = sdscatprintf(sdsempty(),
            "ACTION=open\nMODE=%s\nONE_TAB=1\nCDP=%s\nTAB_ID=%s\nURL=%s\n"
            "PROOF=created single sticky tab.\n",
            mode, cdp_base(), id ? id : "?", url);
        cJSON_Delete(tab);
        if (want_visible_open()) {
            sds vis = open_in_browser_app(url);
            res = sdscat(res, "\n"); res = sdscat(res, vis); sdsfree(vis);
        }
        return res;
    }
    const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(tab, "id"));
    const char *ws = cJSON_GetStringValue(cJSON_GetObjectItem(tab, "webSocketDebuggerUrl"));
    sticky_save(id); cdp_activate(id);
    if (!ws || !ws[0]) { cJSON_Delete(tab); return sdsnew("ERROR: tab has no webSocketDebuggerUrl"); }
    sds nav = cdp_page_navigate(ws, url);
    usleep(400000);
    cJSON *now = cdp_find_tab(id);
    const char *tu = now ? cJSON_GetStringValue(cJSON_GetObjectItem(now, "url")) : url;
    const char *title = now ? cJSON_GetStringValue(cJSON_GetObjectItem(now, "title")) : "";
    sds res = sdscatprintf(sdsempty(),
        "ACTION=open\nMODE=%s\nONE_TAB=1\nCDP=%s\nTAB_ID=%s\nURL=%s\nTITLE=%s\n"
        "PROOF=navigated sticky tab (no new tab).\nNAV_RESULT=%s\n",
        mode, cdp_base(), id ? id : "?", tu ? tu : url, title ? title : "", nav ? nav : "");
    if (nav) sdsfree(nav);
    if (now) cJSON_Delete(now);
    cJSON_Delete(tab);
    if (want_visible_open()) {
        sds vis = open_in_browser_app(url);
        res = sdscat(res, "\n"); res = sdscat(res, vis); sdsfree(vis);
    }
    return res;
}

static cJSON *sticky_tab_obj(void) {
    sds sid = sticky_load();
    cJSON *tab = NULL;
    if (sid) { tab = cdp_find_tab(sid); sdsfree(sid); }
    if (!tab) tab = cdp_first_page_tab();
    if (tab) {
        const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(tab, "id"));
        sticky_save(id); cdp_activate(id);
    }
    return tab;
}


static sds cdp_close_tab(const char *tab_id) {
    if (!tab_id || !tab_id[0]) return sdsnew("ERROR: id required");
    char url[640];
    snprintf(url, sizeof(url), "%s/json/close/%s", cdp_base(), tab_id);
    sds body = NULL;
    long http = cdp_http("GET", url, &body);
    sds res = sdscatprintf(sdsempty(), "ACTION=close\nTAB_ID=%s\nHTTP=%ld\nBODY=%s\n",
                           tab_id, http, body ? body : "");
    if (body) sdsfree(body);
    return res;
}

/* Close every page tab except sticky (tab hygiene). */
static sds cdp_close_others(void) {
    cJSON *keep = sticky_tab_obj();
    const char *keep_id = keep ? cJSON_GetStringValue(cJSON_GetObjectItem(keep, "id")) : NULL;
    char url[512];
    snprintf(url, sizeof(url), "%s/json", cdp_base());
    sds body = NULL;
    if (cdp_http("GET", url, &body) != 200 || !body) {
        if (keep) cJSON_Delete(keep);
        if (body) sdsfree(body);
        return sdsnew("ERROR: cannot list tabs for close_others");
    }
    cJSON *arr = cJSON_Parse(body);
    sdsfree(body);
    if (!arr || !cJSON_IsArray(arr)) {
        if (keep) cJSON_Delete(keep);
        if (arr) cJSON_Delete(arr);
        return sdsnew("ERROR: /json not array");
    }
    int closed = 0, kept = 0;
    sds out = sdscatprintf(sdsempty(), "ACTION=close_others\nKEEP=%s\n", keep_id ? keep_id : "(none)");
    int n = cJSON_GetArraySize(arr);
    for (int i = 0; i < n; i++) {
        cJSON *t = cJSON_GetArrayItem(arr, i);
        const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(t, "type"));
        const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(t, "id"));
        const char *tu = cJSON_GetStringValue(cJSON_GetObjectItem(t, "url"));
        if (!id) continue;
        if (type && strcmp(type, "page") != 0 && strcmp(type, "webview") != 0) continue;
        if (keep_id && strcmp(id, keep_id) == 0) {
            kept++;
            out = sdscatprintf(out, "KEEP_URL=%s\n", tu ? tu : "");
            continue;
        }
        /* never try to close sticky; close junk */
        sds r = cdp_close_tab(id);
        out = sdscatprintf(out, "CLOSED=%s url=%s\n", id, tu ? tu : "");
        sdsfree(r);
        closed++;
    }
    out = sdscatprintf(out, "CLOSED_N=%d KEPT_N=%d\nONE_TAB_POLICY=1\n", closed, kept);
    if (keep) cJSON_Delete(keep);
    cJSON_Delete(arr);
    return out;
}

static sds act_on_sticky(const char *action, cJSON *args) {
    cJSON *tab = sticky_tab_obj();
    if (!tab) return sdsnew("ERROR: no sticky/page tab (open a url first)");
    const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(tab, "id"));
    const char *ws = cJSON_GetStringValue(cJSON_GetObjectItem(tab, "webSocketDebuggerUrl"));
    const char *cur_url = cJSON_GetStringValue(cJSON_GetObjectItem(tab, "url"));
    const char *title = cJSON_GetStringValue(cJSON_GetObjectItem(tab, "title"));
    if (!ws) { cJSON_Delete(tab); return sdsnew("ERROR: no webSocketDebuggerUrl"); }

    const char *selector = cJSON_GetStringValue(cJSON_GetObjectItem(args, "selector"));
    const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(args, "text"));
    const char *expression = cJSON_GetStringValue(cJSON_GetObjectItem(args, "expression"));
    cJSON *jx = cJSON_GetObjectItem(args, "x");
    cJSON *jy = cJSON_GetObjectItem(args, "y");

    sds res = sdscatprintf(sdsempty(),
        "ACTION=%s\nONE_TAB=1\nTAB_ID=%s\nURL=%s\nTITLE=%s\n",
        action, id ? id : "?", cur_url ? cur_url : "", title ? title : "");

    if (strcmp(action, "eval") == 0 || strcmp(action, "evaluate") == 0) {
        if (!expression || !expression[0]) { cJSON_Delete(tab); sdsfree(res); return sdsnew("ERROR: expression required"); }
        sds raw = cdp_eval_js(ws, expression);
        sds val = json_get_eval_value(raw);
        res = sdscatprintf(res, "PROOF=Runtime.evaluate\nRESULT=%s\n", val ? val : "");
        if (val) sdsfree(val); if (raw) sdsfree(raw);
        cJSON_Delete(tab); return res;
    }

    if (strcmp(action, "snapshot") == 0 || strcmp(action, "content") == 0) {
        const char *snap_js =
            "(() => {"
            "  const pick = (els) => Array.from(els).slice(0,40).map(e => ({"
            "    tag: e.tagName, id: e.id||'',"
            "    text: ((e.innerText||e.value||e.getAttribute('aria-label')||'')+'' ).trim().slice(0,80),"
            "    href: e.href||null, type: e.type||null"
            "  })).filter(x => x.text || x.href);"
            "  return JSON.stringify({"
            "    url: location.href, title: document.title,"
            "    buttons: pick(document.querySelectorAll('button,a,[role=button],input[type=submit]')),"
            "    inputs: pick(document.querySelectorAll('input,textarea,select')),"
            "    h1: ((document.querySelector('h1')||{}).innerText||'')+''"
            "  });"
            "})()";
        sds raw = cdp_eval_js(ws, snap_js);
        sds val = json_get_eval_value(raw);
        res = sdscatprintf(res, "PROOF=snapshot\nRESULT=%s\n", val ? val : (raw ? raw : ""));
        if (val) sdsfree(val); if (raw) sdsfree(raw);
        cJSON_Delete(tab); return res;
    }

    if (strcmp(action, "click") == 0) {
        if (cJSON_IsNumber(jx) && cJSON_IsNumber(jy)) {
            double x = jx->valuedouble, y = jy->valuedouble;
            char msg[512];
            snprintf(msg, sizeof(msg),
                "{\"id\":20,\"method\":\"Input.dispatchMouseEvent\",\"params\":{"
                "\"type\":\"mousePressed\",\"x\":%.1f,\"y\":%.1f,\"button\":\"left\",\"clickCount\":1}}", x, y);
            sds r1 = cdp_ws_call(ws, msg);
            snprintf(msg, sizeof(msg),
                "{\"id\":21,\"method\":\"Input.dispatchMouseEvent\",\"params\":{"
                "\"type\":\"mouseReleased\",\"x\":%.1f,\"y\":%.1f,\"button\":\"left\",\"clickCount\":1}}", x, y);
            sds r2 = cdp_ws_call(ws, msg);
            usleep(300000);
            cJSON *now = cdp_find_tab(id);
            const char *nu = now ? cJSON_GetStringValue(cJSON_GetObjectItem(now, "url")) : "";
            res = sdscatprintf(res, "PROOF=click_xy x=%.1f y=%.1f\nAFTER_URL=%s\nR1=%s\nR2=%s\n",
                x, y, nu ? nu : "", r1 ? r1 : "", r2 ? r2 : "");
            if (r1) sdsfree(r1); if (r2) sdsfree(r2); if (now) cJSON_Delete(now);
            cJSON_Delete(tab); return res;
        }
        sds sel_e = js_escape(selector ? selector : "");
        sds txt_e = js_escape(text ? text : "");
        /* Fail-closed click: only real controls, short labels (<=48), no body/email text. */
        sds expr = sdscatprintf(sdsempty(),
            "(() => {"
            "  var sel = '%s'; var text = '%s'; var el = null;"
            "  function lab(e) {"
            "    var s = (e.innerText || e.value || e.getAttribute('aria-label') || e.getAttribute('title') || e.getAttribute('placeholder') || '') + '';"
            "    var o = '', sp = 0;"
            "    for (var i = 0; i < s.length; i++) {"
            "      var c = s.charAt(i);"
            "      if (c === ' ' || c === String.fromCharCode(9) || c === String.fromCharCode(10) || c === String.fromCharCode(13)) {"
            "        if (!sp) { o += ' '; sp = 1; }"
            "      } else { o += c; sp = 0; }"
            "    }"
            "    while (o.length && o.charAt(0) === ' ') o = o.substring(1);"
            "    while (o.length && o.charAt(o.length-1) === ' ') o = o.substring(0, o.length-1);"
            "    return o;"
            "  }"
            "  function isCtrl(e) {"
            "    if (!e) return false;"
            "    var t = (e.tagName || '').toLowerCase();"
            "    if (t === 'a' || t === 'button' || t === 'summary') return true;"
            "    if (t === 'input') { var ty = (e.type || '').toLowerCase(); return ty === 'button' || ty === 'submit' || ty === 'reset'; }"
            "    return e.getAttribute && e.getAttribute('role') === 'button';"
            "  }"
            "  if (sel) { try { el = document.querySelector(sel); } catch (e) {} }"
            "  if (el && !isCtrl(el) && !sel) el = null;"
            "  if (!el && text) {"
            "    var needles = text.toLowerCase().trim();"
            "    if (needles.length < 2) return JSON.stringify({ok:false, err:'text_too_short', url:location.href});"
            "    var ctrls = Array.from(document.querySelectorAll('a,button,input[type=button],input[type=submit],input[type=reset],[role=button],summary'));"
            "    var short = [];"
            "    for (var i = 0; i < ctrls.length; i++) { var L = lab(ctrls[i]); if (L && L.length > 0 && L.length <= 48) short.push(ctrls[i]); }"
            "    for (var j = 0; j < short.length; j++) { if (lab(short[j]).toLowerCase() === needles) { el = short[j]; break; } }"
            "    if (!el) { for (var k = 0; k < short.length; k++) { var Lk = lab(short[k]).toLowerCase(); if (needles.length >= 3 && Lk.indexOf(needles) === 0) { el = short[k]; break; } } }"
            "    if (!el && needles.length >= 4) {"
            "      var cands = [];"
            "      for (var m = 0; m < short.length; m++) { if (lab(short[m]).toLowerCase().indexOf(needles) >= 0) cands.push(short[m]); }"
            "      if (cands.length === 1) el = cands[0];"
            "      else if (cands.length > 1) {"
            "        var matches = [];"
            "        for (var n = 0; n < cands.length && n < 8; n++) matches.push({tag:cands[n].tagName, text:lab(cands[n]).slice(0,48)});"
            "        return JSON.stringify({ok:false, err:'ambiguous', matches:matches, url:location.href});"
            "      }"
            "    }"
            "  }"
            "  if (!el) return JSON.stringify({ok:false, err:'not_found', hint:'use snapshot; only short button/link labels', url:location.href});"
            "  if (!isCtrl(el) && !sel) return JSON.stringify({ok:false, err:'not_a_control', tag:el.tagName, text:lab(el).slice(0,80), url:location.href});"
            "  el.scrollIntoView({block:'center', inline:'center'});"
            "  var r = el.getBoundingClientRect();"
            "  if (el.focus) el.focus(); el.click();"
            "  return JSON.stringify({ok:true, tag:el.tagName, id:el.id||'', text:lab(el).slice(0,100), href:el.href||null, x:Math.round(r.x+r.width/2), y:Math.round(r.y+r.height/2), url:location.href});"
            "})()", sel_e, txt_e);
        sdsfree(sel_e); sdsfree(txt_e);
        sds raw = cdp_eval_js(ws, expr); sdsfree(expr);
        sds val = json_get_eval_value(raw);
        usleep(350000);
        cJSON *now = cdp_find_tab(id);
        const char *nu = now ? cJSON_GetStringValue(cJSON_GetObjectItem(now, "url")) : "";
        res = sdscatprintf(res, "PROOF=click_dom\nRESULT=%s\nAFTER_URL=%s\n", val ? val : (raw ? raw : ""), nu ? nu : "");
        if (val) sdsfree(val); if (raw) sdsfree(raw); if (now) cJSON_Delete(now);
        cJSON_Delete(tab); return res;
    }

    if (strcmp(action, "type") == 0 || strcmp(action, "fill") == 0) {
        if (!text) { cJSON_Delete(tab); sdsfree(res); return sdsnew("ERROR: text required"); }
        sds sel_e = js_escape(selector ? selector : "");
        sds txt_e = js_escape(text);
        sds expr = sdscatprintf(sdsempty(),
            "(() => {"
            "  const sel = '%s'; const text = '%s'; let el = null;"
            "  if (sel) { try { el = document.querySelector(sel); } catch(e) {} }"
            "  if (!el) el = document.querySelector('input:not([type=hidden]),textarea,[contenteditable=true]');"
            "  if (!el) return JSON.stringify({ok:false, err:'no_input', url:location.href});"
            "  el.focus();"
            "  if (el.isContentEditable) el.innerText = text;"
            "  else { el.value = text; el.dispatchEvent(new Event('input', {bubbles:true})); el.dispatchEvent(new Event('change', {bubbles:true})); }"
            "  return JSON.stringify({ok:true, tag:el.tagName, id:el.id||'', name:el.name||'', url:location.href});"
            "})()", sel_e, txt_e);
        sdsfree(sel_e); sdsfree(txt_e);
        sds raw = cdp_eval_js(ws, expr); sdsfree(expr);
        sds val = json_get_eval_value(raw);
        res = sdscatprintf(res, "PROOF=type\nRESULT=%s\n", val ? val : (raw ? raw : ""));
        if (val) sdsfree(val); if (raw) sdsfree(raw);
        cJSON_Delete(tab); return res;
    }

    if (strcmp(action, "press") == 0) {
        const char *key = (text && text[0]) ? text : "Enter";
        sds key_e = js_escape(key);
        sds expr = sdscatprintf(sdsempty(),
            "(() => {"
            "  const key = '%s';"
            "  const el = document.activeElement || document.body;"
            "  el.dispatchEvent(new KeyboardEvent('keydown', {key:key, bubbles:true}));"
            "  el.dispatchEvent(new KeyboardEvent('keyup', {key:key, bubbles:true}));"
            "  if (key === 'Enter' && el.form) { try { el.form.requestSubmit ? el.form.requestSubmit() : el.form.submit(); } catch(e) {} }"
            "  return JSON.stringify({ok:true, key:key, url:location.href});"
            "})()", key_e);
        sdsfree(key_e);
        sds raw = cdp_eval_js(ws, expr); sdsfree(expr);
        sds val = json_get_eval_value(raw);
        res = sdscatprintf(res, "PROOF=press\nRESULT=%s\n", val ? val : (raw ? raw : ""));
        if (val) sdsfree(val); if (raw) sdsfree(raw);
        cJSON_Delete(tab); return res;
    }

    cJSON_Delete(tab); sdsfree(res);
    return sdscatprintf(sdsempty(), "ERROR: unhandled act %s", action);
}

static sds cdp_list_tabs(void) {
    char url[512];
    snprintf(url, sizeof(url), "%s/json", cdp_base());
    sds body = NULL;
    long http = cdp_http("GET", url, &body);
    if (http != 200 || !body) {
        sds res = sdscatprintf(sdsempty(), "ACTION=tabs\nCDP=%s\nHTTP=%ld\nERROR=%s\n",
                               cdp_base(), http, body ? body : "empty");
        if (body) sdsfree(body);
        return res;
    }
    cJSON *arr = cJSON_Parse(body); sdsfree(body);
    if (!arr || !cJSON_IsArray(arr)) { if (arr) cJSON_Delete(arr); return sdsnew("ERROR: /json not array"); }
    sds sticky = sticky_load();
    sds out = sdscatprintf(sdsempty(), "ACTION=tabs\nCDP=%s\nCOUNT=%d\nSTICKY=%s\n",
                           cdp_base(), cJSON_GetArraySize(arr), sticky ? sticky : "(none)");
    int n = cJSON_GetArraySize(arr), pages = 0;
    for (int i = 0; i < n && pages < 40; i++) {
        cJSON *t = cJSON_GetArrayItem(arr, i);
        const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(t, "type"));
        const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(t, "id"));
        const char *title = cJSON_GetStringValue(cJSON_GetObjectItem(t, "title"));
        const char *tu = cJSON_GetStringValue(cJSON_GetObjectItem(t, "url"));
        if (type && strcmp(type, "page") != 0 && strcmp(type, "webview") != 0) continue;
        pages++;
        const char *mark = (sticky && id && strcmp(sticky, id) == 0) ? " [STICKY]" : "";
        out = sdscatprintf(out, "- id=%s title=%s url=%s%s\n", id ? id : "?", title ? title : "", tu ? tu : "", mark);
    }
    out = sdscatprintf(out, "PAGE_TABS=%d\nONE_TAB_POLICY=open navigates sticky; use click/type/snapshot on same tab\n", pages);
    if (sticky) sdsfree(sticky);
    cJSON_Delete(arr);
    return out;
}

static sds normalize_url(const char *url, char *urlbuf, size_t urlbuf_sz) {
    if (!url || !url[0]) return NULL;
    if (strcmp(url, "youtube") == 0 || strcmp(url, "yt") == 0) {
        snprintf(urlbuf, urlbuf_sz, "https://www.youtube.com"); return urlbuf;
    }
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) {
        snprintf(urlbuf, urlbuf_sz, "https://%s", url); return urlbuf;
    }
    snprintf(urlbuf, urlbuf_sz, "%s", url); return urlbuf;
}

/* There is exactly ONE sticky tab and one shared CDP session, but up to 4 chats
 * can run tools concurrently. Without this lock two chats interleave clicks and
 * navigations on the same tab and corrupt each other's browsing state. */
static pthread_mutex_t browser_lock = PTHREAD_MUTEX_INITIALIZER;

static sds browser_tool_run_locked(cJSON *args);

sds browser_tool_run(cJSON *args) {
    pthread_mutex_lock(&browser_lock);
    sds r = browser_tool_run_locked(args);
    pthread_mutex_unlock(&browser_lock);
    return r;
}

static sds browser_tool_run_locked(cJSON *args) {
    if (!args) args = cJSON_CreateObject();
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    const char *url = cJSON_GetStringValue(cJSON_GetObjectItem(args, "url"));
    if (!action || !action[0]) action = (url && url[0]) ? "open" : "tabs";

    if (strcmp(action, "status") == 0 || strcmp(action, "doctor") == 0) {
        sds body = NULL; char u[512];
        snprintf(u, sizeof(u), "%s/json/version", cdp_base());
        long http = cdp_http("GET", u, &body);
        sds sticky = sticky_load();
        sds res = sdscatprintf(sdsempty(),
            "ACTION=status\nCDP=%s\nHTTP=%ld\nALIVE=%s\nSTICKY_TAB=%s\nONE_TAB_POLICY=1\nBROWSER_APP=%s\nVERSION=%s\n",
            cdp_base(), http, (http == 200) ? "yes" : "no", sticky ? sticky : "(none)", browser_app(), body ? body : "");
        if (sticky) sdsfree(sticky); if (body) sdsfree(body);
        return res;
    }
    if (strcmp(action, "tabs") == 0 || strcmp(action, "list") == 0) return cdp_list_tabs();

    if (strcmp(action, "open") == 0 || strcmp(action, "navigate") == 0 || strcmp(action, "goto") == 0) {
        if (!url || !url[0]) return sdsnew("ERROR: url required for open/navigate");
        char urlbuf[PATH_MAX]; url = normalize_url(url, urlbuf, sizeof(urlbuf));
        if (cdp_alive()) return cdp_goto_one_tab(url, 0);
        return open_in_browser_app(url);
    }
    if (strcmp(action, "new_tab") == 0) {
        if (!url || !url[0]) return sdsnew("ERROR: url required for new_tab");
        char urlbuf[PATH_MAX]; url = normalize_url(url, urlbuf, sizeof(urlbuf));
        if (cdp_alive()) return cdp_goto_one_tab(url, 1);
        return open_in_browser_app(url);
    }
    if (strcmp(action, "open_visible") == 0 || strcmp(action, "open_user") == 0) {
        if (!url || !url[0]) return sdsnew("ERROR: url required");
        char urlbuf[PATH_MAX]; url = normalize_url(url, urlbuf, sizeof(urlbuf));
        sds out = sdsempty();
        if (cdp_alive()) { sds nav = cdp_goto_one_tab(url, 0); out = sdscat(out, nav); sdsfree(nav); out = sdscat(out, "\n"); }
        sds vis = open_in_browser_app(url); out = sdscat(out, vis); sdsfree(vis);
        return out;
    }
    if (strcmp(action, "reset_sticky") == 0) {
        unlink(STICKY_TAB_PATH);
        return sdsnew("ACTION=reset_sticky\nOK=1\n");
    }
    if (strcmp(action, "close_others") == 0 || strcmp(action, "cleanup") == 0) {
        if (!cdp_alive()) return sdsnew("ERROR: CDP not alive");
        return cdp_close_others();
    }
    if (strcmp(action, "close") == 0) {
        if (!cdp_alive()) return sdsnew("ERROR: CDP not alive");
        const char *tid = cJSON_GetStringValue(cJSON_GetObjectItem(args, "tab_id"));
        if (!tid || !tid[0]) {
            /* close sticky and clear */
            sds sid = sticky_load();
            if (!sid) return sdsnew("ERROR: no sticky to close");
            sds r = cdp_close_tab(sid);
            unlink(STICKY_TAB_PATH);
            sdsfree(sid);
            return r;
        }
        return cdp_close_tab(tid);
    }
    if (strcmp(action, "click") == 0 || strcmp(action, "type") == 0 || strcmp(action, "fill") == 0 ||
        strcmp(action, "eval") == 0 || strcmp(action, "evaluate") == 0 ||
        strcmp(action, "snapshot") == 0 || strcmp(action, "content") == 0 ||
        strcmp(action, "press") == 0) {
        if (!cdp_alive()) return sdsnew("ERROR: CDP not alive");
        return act_on_sticky(action, args);
    }
    return sdscatprintf(sdsempty(),
        "ERROR: unknown browser action '%s'. "
        "Use open|navigate|tabs|status|click|type|snapshot|eval|press|close|close_others|new_tab|open_visible|reset_sticky",
        action);
}
