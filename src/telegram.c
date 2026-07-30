#include "alpha.h"
#include <curl/curl.h>

typedef struct {
    sds body;
} tbuf_t;

static size_t tg_write(char *ptr, size_t size, size_t nmemb, void *ud) {
    tbuf_t *b = ud;
    b->body = sdscatlen(b->body, ptr, size * nmemb);
    return size * nmemb;
}

static sds tg_api(const char *token, const char *method, const char *json_body) {
    sds url = sdscatprintf(sdsempty(), "https://api.telegram.org/bot%s/%s", token, method);
    CURL *curl = curl_easy_init();
    tbuf_t buf = { .body = sdsempty() };
    if (!curl) {
        sdsfree(url);
        return sdsnew("ERROR curl init");
    }
    struct curl_slist *hdrs = NULL;
    if (json_body) hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (hdrs) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    if (json_body) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tg_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, json_body ? 60L : 50L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    CURLcode rc = curl_easy_perform(curl);
    if (hdrs) curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    sdsfree(url);
    if (rc != CURLE_OK) {
        sdsfree(buf.body);
        return sdscatprintf(sdsempty(), "ERROR: %s", curl_easy_strerror(rc));
    }
    return buf.body;
}

/* Never split inside a UTF-8 sequence: Telegram rejects the whole message with
 * 400 "strings must be encoded in UTF-8", so a long reply containing any
 * non-ASCII (umlauts, emoji, box drawing) silently vanished. */
static size_t utf8_safe_len(const char *s, size_t max) {
    size_t n = max;
    if (n == 0) return 0;
    /* Walk back off any continuation bytes to the start of the character. */
    while (n > 0 && ((unsigned char)s[n] & 0xC0) == 0x80) n--;
    if (n == 0) return max;   /* pathological: no boundary found, send as-is */
    return n;
}

/* Test seam: the suite substitutes a recorder so the real chunking path is
 * exercised without a network. Production always uses tg_api. */
#ifndef ALPHA_TG_SEND_HOOK
#define ALPHA_TG_SEND_HOOK(tok, body) tg_api((tok), "sendMessage", (body))
#endif

static void tg_send(const char *token, long long chat_id, const char *text) {
    if (!text) text = "";
    size_t len = strlen(text);
    size_t off = 0;
    while (off < len || off == 0) {
        size_t n = len - off;
        if (n > 3500) n = utf8_safe_len(text + off, 3500);
        sds chunk = sdsnewlen(text + off, n);
        sds esc = sdsempty();
        for (size_t i = 0; i < sdslen(chunk); i++) {
            char c = chunk[i];
            if (c == '\\' || c == '"') {
                esc = sdscatlen(esc, "\\", 1);
                esc = sdscatlen(esc, &c, 1);
            } else if (c == '\n') esc = sdscat(esc, "\\n");
            else if (c == '\r') esc = sdscat(esc, "\\r");
            else if ((unsigned char)c < 0x20) continue;
            else esc = sdscatlen(esc, &c, 1);
        }
        sds body = sdscatprintf(sdsempty(),
            "{\"chat_id\":%lld,\"text\":\"%s\"}", chat_id, esc);
        sds r = ALPHA_TG_SEND_HOOK(token, body);
        /* A failed send used to be discarded silently — the user just saw
         * nothing. At minimum make it visible in the log. */
        if (r && (strncmp(r, "ERROR", 5) == 0 || strstr(r, "\"ok\":false")))
            fprintf(stderr, "[alpha-tg] sendMessage FAILED chat=%lld: %.200s\n", chat_id, r);
        sdsfree(r);
        sdsfree(body);
        sdsfree(esc);
        sdsfree(chunk);
        if (n == 0) break;
        off += n;
        if (off >= len) break;
    }
}

static int allowed(const char *allow, long long chat_id) {
    if (!allow || !allow[0] || strcmp(allow, "*") == 0) return 1;
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", allow);
    char *save = NULL;
    for (char *tok = strtok_r(buf, ", \t", &save); tok; tok = strtok_r(NULL, ", \t", &save)) {
        if (atoll(tok) == chat_id) return 1;
    }
    return 0;
}

static int load_offset(const char *path, long long *off) {
    *off = 0;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (fscanf(f, "%lld", off) != 1) *off = 0;
    fclose(f);
    return 1;
}

static void save_offset(const char *path, long long off) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "%lld\n", off);
    fclose(f);
}

/* Per-chat cwd: /cwd in one chat must not silently move every other chat. */
#define ALPHA_MAX_CHAT_CWD 32
static struct {
    long long chat_id;
    char cwd[PATH_MAX];
} chat_cwds[ALPHA_MAX_CHAT_CWD];
static int chat_cwd_n = 0;

/* Read by 4 worker threads and written by the poll thread — must be locked.
 * Measured unlocked: ~90 wrong-value reads per run under contention. */
static pthread_mutex_t chat_cwd_lock = PTHREAD_MUTEX_INITIALIZER;

/* Copies into caller storage: returning an interior pointer would let another
 * thread overwrite the buffer while it is in use. */
static int chat_cwd_get_copy(long long chat_id, char *out, size_t outsz) {
    int found = 0;
    pthread_mutex_lock(&chat_cwd_lock);
    for (int i = 0; i < chat_cwd_n; i++) {
        if (chat_cwds[i].chat_id == chat_id) {
            snprintf(out, outsz, "%s", chat_cwds[i].cwd);
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&chat_cwd_lock);
    return found;
}

static void chat_cwd_set(long long chat_id, const char *cwd) {
    pthread_mutex_lock(&chat_cwd_lock);
    for (int i = 0; i < chat_cwd_n; i++) {
        if (chat_cwds[i].chat_id == chat_id) {
            snprintf(chat_cwds[i].cwd, sizeof(chat_cwds[i].cwd), "%s", cwd);
            pthread_mutex_unlock(&chat_cwd_lock);
            return;
        }
    }
    if (chat_cwd_n >= ALPHA_MAX_CHAT_CWD) chat_cwd_n = 0;   /* simple wrap */
    chat_cwds[chat_cwd_n].chat_id = chat_id;
    snprintf(chat_cwds[chat_cwd_n].cwd, sizeof(chat_cwds[chat_cwd_n].cwd), "%s", cwd);
    chat_cwd_n++;
    pthread_mutex_unlock(&chat_cwd_lock);
}

static void session_path_for_chat(char *out, size_t outsz, long long chat_id) {
    const char *root = getenv("ALPHA_ROOT");
    if (!root || !root[0]) root = ".";
    snprintf(out, outsz, "%s/sessions/chat_%lld.json", root, chat_id);
}

/* Work queue.
 *
 * The poll loop must never block on the agent: one 20-turn request could
 * otherwise freeze every other chat for tens of minutes (the bot looks dead).
 * Requests are queued and executed by worker threads, while a chat that is
 * already running is kept strictly serialized so its session file and message
 * order stay consistent. */
#define ALPHA_WORKERS      4
#define ALPHA_QUEUE_MAX    64

typedef struct job_s {
    long long chat_id;
    char *text;
    struct job_s *next;
} job_t;

typedef struct {
    job_t *head, *tail;
    int count;
    long long busy[ALPHA_WORKERS];   /* chats currently being executed */
    int nbusy;
    pthread_mutex_t lock;
    pthread_cond_t cv;
    alpha_cfg_t *cfg;
    const char *token;
} queue_t;

static queue_t g_queue;

static int q_chat_busy(queue_t *q, long long chat_id) {
    for (int i = 0; i < q->nbusy; i++) if (q->busy[i] == chat_id) return 1;
    return 0;
}

static void q_mark_busy(queue_t *q, long long chat_id) {
    if (q->nbusy < ALPHA_WORKERS) q->busy[q->nbusy++] = chat_id;
}

static void q_clear_busy(queue_t *q, long long chat_id) {
    for (int i = 0; i < q->nbusy; i++) {
        if (q->busy[i] == chat_id) {
            q->busy[i] = q->busy[--q->nbusy];
            return;
        }
    }
}

static int job_is_quick(const char *text);

typedef struct {
    queue_t *q;
    int quick_only;   /* reserved lane: only takes short messages */
} worker_arg_t;

/* Caller holds the lock. Take the first job whose chat is not already running.
 * A quick_only worker skips long requests entirely. */
static job_t *q_take_ready(queue_t *q, int quick_only) {
    job_t *prev = NULL, *j = q->head;
    while (j) {
        if (quick_only && !job_is_quick(j->text)) { prev = j; j = j->next; continue; }
        if (!q_chat_busy(q, j->chat_id)) {
            if (prev) prev->next = j->next;
            else q->head = j->next;
            if (q->tail == j) q->tail = prev;
            q->count--;
            j->next = NULL;
            return j;
        }
        prev = j;
        j = j->next;
    }
    return NULL;
}

static int q_push(queue_t *q, long long chat_id, const char *text) {
    pthread_mutex_lock(&q->lock);
    if (q->count >= ALPHA_QUEUE_MAX) {
        pthread_mutex_unlock(&q->lock);
        return 0;
    }
    job_t *j = calloc(1, sizeof(*j));
    if (!j) {
        pthread_mutex_unlock(&q->lock);
        return 0;
    }
    j->chat_id = chat_id;
    j->text = strdup(text ? text : "");
    if (q->tail) q->tail->next = j;
    else q->head = j;
    q->tail = j;
    q->count++;
    pthread_cond_signal(&q->cv);
    pthread_mutex_unlock(&q->lock);
    return 1;
}

/* One worker is reserved for short commands so a burst of long builds cannot
 * starve simple messages (measured: a 'ping' behind 4 long jobs waited for all
 * of them to finish). */
/* Message length says nothing about how long a request runs: "Go" is 2 chars
 * and can kick off an hour-long build, which would occupy the reserved lane and
 * defeat its whole purpose (measured: a 'ping' still waited behind it).
 *
 * Only messages that are answerable without touching tools qualify. Anything
 * else goes to the normal lane, where being slow is expected. */
static int job_is_quick(const char *text) {
    if (!text || !text[0]) return 0;
    if (strchr(text, '\n')) return 0;
    if (strlen(text) >= 24) return 0;

    static const char *chatty[] = {
        "ping", "hi", "hey", "hello", "yo", "hallo", "moin",
        "status", "thanks", "danke", "ok", "okay", "stop", "help",
        NULL
    };
    char low[32];
    size_t n = 0;
    for (; text[n] && n + 1 < sizeof(low); n++)
        low[n] = (char)tolower((unsigned char)text[n]);
    low[n] = 0;
    while (n && (low[n-1] == '!' || low[n-1] == '.' ||
                 low[n-1] == '?' || low[n-1] == ' '))
        low[--n] = 0;

    for (int i = 0; chatty[i]; i++)
        if (strcmp(low, chatty[i]) == 0) return 1;
    return 0;
}

static void *worker_main(void *arg) {
    worker_arg_t *wa = arg;
    queue_t *q = wa->q;
    int quick_only = wa->quick_only;
    for (;;) {
        pthread_mutex_lock(&q->lock);
        job_t *j = NULL;
        while ((j = q_take_ready(q, quick_only)) == NULL)
            pthread_cond_wait(&q->cv, &q->lock);
        q_mark_busy(q, j->chat_id);
        pthread_mutex_unlock(&q->lock);

        char spath[PATH_MAX];
        session_path_for_chat(spath, sizeof(spath), j->chat_id);

        alpha_cfg_t turn_cfg = *q->cfg;
        char ccwd[PATH_MAX];
        if (chat_cwd_get_copy(j->chat_id, ccwd, sizeof(ccwd))) turn_cfg.cwd = ccwd;

        fprintf(stderr, "[alpha-tg] chat=%lld run: %.60s\n", j->chat_id, j->text);
        sds ans = agent_run_session(&turn_cfg, spath, j->text);
        if (ans && ans[0]) tg_send(q->token, j->chat_id, ans);
        else tg_send(q->token, j->chat_id, "(empty reply)");
        sdsfree(ans);
        fprintf(stderr, "[alpha-tg] chat=%lld done\n", j->chat_id);

        pthread_mutex_lock(&q->lock);
        q_clear_busy(q, j->chat_id);
        /* A queued message for this chat may now be runnable. */
        pthread_cond_broadcast(&q->cv);
        pthread_mutex_unlock(&q->lock);

        free(j->text);
        free(j);
    }
    return NULL;
}

int telegram_run(alpha_cfg_t *cfg, const char *token, const char *allow_csv) {
    if (!token || !token[0]) {
        fprintf(stderr, "[alpha-tg] missing TELEGRAM token\n");
        return 1;
    }
    char off_path[PATH_MAX];
    const char *root = getenv("ALPHA_ROOT");
    if (!root || !root[0]) root = ".";
    snprintf(off_path, sizeof(off_path), "%s/sessions/tg_offset", root);
    system("mkdir -p sessions");

    long long offset = 0;
    load_offset(off_path, &offset);

    g_queue.cfg = cfg;
    g_queue.token = token;
    pthread_mutex_init(&g_queue.lock, NULL);
    pthread_cond_init(&g_queue.cv, NULL);
    static worker_arg_t wargs[ALPHA_WORKERS];
    for (int i = 0; i < ALPHA_WORKERS; i++) {
        wargs[i].q = &g_queue;
        /* Last worker is the reserved fast lane. */
        wargs[i].quick_only = (i == ALPHA_WORKERS - 1);
        pthread_t th;
        if (pthread_create(&th, NULL, worker_main, &wargs[i]) == 0) pthread_detach(th);
    }

    fprintf(stderr, "[alpha-tg] Agent Alpha online  model=%s  allow=%s  cwd=%s  memory=on\n",
            cfg->model ? cfg->model : "?",
            allow_csv && allow_csv[0] ? allow_csv : "*",
            cfg->cwd ? cfg->cwd : ".");

    /* drop pending backlog once at start */
    {
        sds body = sdscatprintf(sdsempty(), "{\"offset\":-1,\"timeout\":0}");
        sds r = tg_api(token, "getUpdates", body);
        sdsfree(body);
        cJSON *rootj = cJSON_Parse(r);
        sdsfree(r);
        if (rootj) {
            cJSON *res = cJSON_GetObjectItem(rootj, "result");
            int n = cJSON_IsArray(res) ? cJSON_GetArraySize(res) : 0;
            if (n > 0) {
                cJSON *last = cJSON_GetArrayItem(res, n - 1);
                cJSON *uid = cJSON_GetObjectItem(last, "update_id");
                if (cJSON_IsNumber(uid)) {
                    offset = (long long)uid->valuedouble + 1;
                    save_offset(off_path, offset);
                }
            }
            cJSON_Delete(rootj);
        }
    }

    int cycles = 0;
    for (;;) {
        sds body = sdscatprintf(sdsempty(),
            "{\"offset\":%lld,\"timeout\":25,\"allowed_updates\":[\"message\"]}",
            offset);
        sds r = tg_api(token, "getUpdates", body);
        sdsfree(body);
        cycles++;
        if (cycles % 3 == 1)
            fprintf(stderr, "[alpha-tg] poll ok offset=%lld cycles=%d\n", offset, cycles);

        if (strncmp(r, "ERROR", 5) == 0) {
            fprintf(stderr, "[alpha-tg] %s\n", r);
            sdsfree(r);
            sleep(2);
            continue;
        }
        cJSON *rootj = cJSON_Parse(r);
        sdsfree(r);
        if (!rootj) {
            sleep(1);
            continue;
        }
        cJSON *res = cJSON_GetObjectItem(rootj, "result");
        int n = cJSON_IsArray(res) ? cJSON_GetArraySize(res) : 0;
        for (int i = 0; i < n; i++) {
            cJSON *u = cJSON_GetArrayItem(res, i);
            cJSON *uid = cJSON_GetObjectItem(u, "update_id");
            if (cJSON_IsNumber(uid)) {
                long long id = (long long)uid->valuedouble;
                if (id + 1 > offset) offset = id + 1;
            }
            cJSON *msg = cJSON_GetObjectItem(u, "message");
            if (!msg) msg = cJSON_GetObjectItem(u, "edited_message");
            if (!msg) continue;
            cJSON *chat = cJSON_GetObjectItem(msg, "chat");
            cJSON *cid = chat ? cJSON_GetObjectItem(chat, "id") : NULL;
            long long chat_id = cid && cJSON_IsNumber(cid) ? (long long)cid->valuedouble : 0;
            if (!allowed(allow_csv, chat_id)) {
                fprintf(stderr, "[alpha-tg] reject chat=%lld\n", chat_id);
                continue;
            }
            const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(msg, "text"));
            if (!text || !text[0]) continue;

            char spath[PATH_MAX];
            session_path_for_chat(spath, sizeof(spath), chat_id);

            if (strcmp(text, "/start") == 0 || strcmp(text, "/help") == 0) {
                tg_send(token, chat_id,
                    "Agent Alpha — OpenClaw-style coding chat on Telegram.\n"
                    "Continuous memory in this chat. Open tools (no pin).\n"
                    "Model: claude-opus-5\n\n"
                    "Talk normally. For code, just say what to change/test.\n"
                    "/status · /cwd <path> · /new (reset memory)\n");
                continue;
            }
            if (strcmp(text, "/new") == 0 || strcmp(text, "/clear") == 0) {
                agent_session_clear(spath);
                tg_send(token, chat_id, "Memory cleared. Fresh conversation.");
                fprintf(stderr, "[alpha-tg] chat=%lld cleared\n", chat_id);
                continue;
            }
            if (strncmp(text, "/cwd ", 5) == 0) {
                const char *p = text + 5;
                while (*p == ' ') p++;
                char newcwd[PATH_MAX];
                if (realpath(p, newcwd)) {
                    chat_cwd_set(chat_id, newcwd);
                    sds m = sdscatprintf(sdsempty(), "cwd = %s", newcwd);
                    tg_send(token, chat_id, m);
                    sdsfree(m);
                } else {
                    tg_send(token, chat_id, "bad path");
                }
                continue;
            }
            if (strcmp(text, "/status") == 0 || strcmp(text, "/cwd") == 0) {
                char st_cwd[PATH_MAX];
                if (!chat_cwd_get_copy(chat_id, st_cwd, sizeof(st_cwd)))
                    snprintf(st_cwd, sizeof(st_cwd), "%s", cfg->cwd ? cfg->cwd : ".");
                sds m = sdscatprintf(sdsempty(),
                    "Agent Alpha (OpenClaw-style session)\n"
                    "model: %s\nbase: %s\ncwd: %s\n"
                    "security: OFF (open tools)\nmemory: %s",
                    cfg->model ? cfg->model : "?",
                    cfg->base_url ? cfg->base_url : "?",
                    st_cwd,
                    spath);
                tg_send(token, chat_id, m);
                sdsfree(m);
                continue;
            }

            /* light instant hellos still OK — also store into memory via agent path for continuity? 
             * Prefer LLM/memory path for "like OpenClaw" except pure /commands.
             * Keep only true ping instant. */
            {
                char low[64];
                size_t ln = 0;
                for (; text[ln] && ln + 1 < sizeof(low); ln++)
                    low[ln] = (char)tolower((unsigned char)text[ln]);
                low[ln] = 0;
                while (ln && (low[ln-1]=='!'||low[ln-1]=='.'||low[ln-1]=='?'||low[ln-1]==' '))
                    low[--ln] = 0;
                if (!strcmp(low, "ping")) {
                    tg_send(token, chat_id, "pong");
                    continue;
                }
            }

            fprintf(stderr, "[alpha-tg] chat=%lld: %.80s\n", chat_id, text);
            /* Commit the offset BEFORE handing off: a crash or restart must not
             * make Telegram redeliver and re-execute the same tools. */
            save_offset(off_path, offset);

            /* Hand off to a worker so polling continues immediately. */
            if (!q_push(&g_queue, chat_id, text))
                tg_send(token, chat_id, "Busy — too many queued requests. Try again shortly.");
        }
        save_offset(off_path, offset);
        cJSON_Delete(rootj);
    }
    return 0;
}
