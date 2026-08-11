#include "alpha.h"
#include <curl/curl.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/file.h>
#include <signal.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

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
            /* Tab is a control char but carries meaning: dropping it turns a
             * Makefile into "missing separator" and flattens indented code. */
            else if (c == '\t') esc = sdscat(esc, "\\t");
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

/* Voice notes.
 *
 * Telegram delivers audio as a file_id, so it takes two calls: getFile for the
 * path, then a plain GET on /file/bot<token>/<path>. Transcription is a local
 * Whisper run via scripts/alpha-transcribe.py -- no API key, and the audio
 * never leaves the machine.
 *
 * Returns the transcript, or NULL if anything failed. */
/* CURLOPT_MAXFILESIZE only rejects up front when the server declares a
 * Content-Length, so the limit is enforced on the received bytes as well.
 * Returning short aborts the transfer. */
typedef struct {
    FILE *f;
    size_t written;
} voice_sink_t;

static size_t voice_write(char *ptr, size_t size, size_t nmemb, void *ud) {
    voice_sink_t *s = ud;
    size_t n = size * nmemb;
    if (s->written + n > ALPHA_VOICE_MAX_BYTES) return 0;
    size_t w = fwrite(ptr, size, nmemb, s->f);
    s->written += w * size;
    return w;
}

/* A voice note's scratch file. The pid alone is not unique: notes are
 * downloaded one per update but a restart within the same second, or any
 * future concurrency, would reuse the path and let one download truncate
 * another's. */
static void voice_tmp_path(char *out, size_t outsz) {
    static unsigned long seq;
    unsigned long n = __atomic_add_fetch(&seq, 1, __ATOMIC_RELAXED);
    snprintf(out, outsz, "/tmp/alpha-voice-%lld-%lu.ogg", (long long)getpid(), n);
}

static int voice_download(const char *token, const char *file_id, char *out, size_t outsz) {
    sds body = sdscatprintf(sdsempty(), "{\"file_id\":\"%s\"}", file_id);
    sds r = tg_api(token, "getFile", body);
    sdsfree(body);
    if (!r) return 0;

    cJSON *root = cJSON_Parse(r);
    sdsfree(r);
    if (!root) return 0;
    cJSON *res = cJSON_GetObjectItem(root, "result");
    const char *fpath = res ? cJSON_GetStringValue(cJSON_GetObjectItem(res, "file_path")) : NULL;
    if (!fpath || !fpath[0]) { cJSON_Delete(root); return 0; }

    voice_tmp_path(out, outsz);
    FILE *f = fopen(out, "wb");
    if (!f) { cJSON_Delete(root); return 0; }
    voice_sink_t sink = { .f = f, .written = 0 };

    sds url = sdscatprintf(sdsempty(), "https://api.telegram.org/file/bot%s/%s", token, fpath);
    cJSON_Delete(root);

    CURL *curl = curl_easy_init();
    int ok = 0;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, voice_write);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
        /* Telegram allows files up to 20 MB. Transcribing one costs minutes of
         * CPU on the poll thread, so refuse oversized audio outright. */
        curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)ALPHA_VOICE_MAX_BYTES);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        ok = (curl_easy_perform(curl) == CURLE_OK);
        curl_easy_cleanup(curl);
    }
    sdsfree(url);
    fclose(f);
    if (!ok) unlink(out);
    return ok;
}

/* Locate scripts/alpha-transcribe.py.
 *
 * ALPHA_ROOT is normally unset and the old code then fell back to ".", which
 * only works when the bot happens to be started from the repo. Launching it
 * from anywhere else -- or setting ALPHA_CWD, which /status advertises --
 * left the script unfindable and every voice note answered "could not
 * transcribe". The install directory is a property of the binary, not of
 * wherever it was launched, so derive it from argv[0] and keep the cwd
 * fallback only as a last resort. */
static void alpha_resolve_install_root(char *root, size_t rootsz) {
    const char *env = getenv("ALPHA_ROOT");
    if (env && env[0]) { snprintf(root, rootsz, "%s", env); return; }

    char exe[PATH_MAX];
    uint32_t sz = sizeof(exe);
#ifdef __APPLE__
    if (_NSGetExecutablePath(exe, &sz) == 0) {
#else
    ssize_t rl = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (rl > 0 && (exe[rl] = 0, 1)) {
#endif
        char resolved[PATH_MAX];
        if (realpath(exe, resolved)) {
            char *slash = strrchr(resolved, '/');
            if (slash) {
                *slash = 0;
                snprintf(root, rootsz, "%s", resolved);
                return;
            }
        }
    }
    snprintf(root, rootsz, ".");
}

/* Cached wrapper: resolution is stable for the life of the process. */
static const char *alpha_install_root(void) {
    static char root[PATH_MAX];
    static int done;
    if (!done) { alpha_resolve_install_root(root, sizeof(root)); done = 1; }
    return root;
}

/* Run the transcriber and collect stdout. Caller frees.
 *
 * On failure the child's stderr is captured and logged: it used to go to
 * /dev/null, so a missing ffmpeg or model surfaced to the user as a bare
 * "could not transcribe" with nothing in the log to act on. */
static sds voice_transcribe(const char *audio_path) {
    char script[PATH_MAX];
    snprintf(script, sizeof(script), "%s/scripts/alpha-transcribe.py",
             alpha_install_root());
    if (access(script, R_OK) != 0) {
        fprintf(stderr, "[alpha-tg] transcriber not found at %s\n", script);
        return NULL;
    }

    int pipefd[2], errfd[2];
    if (pipe(pipefd) != 0) return NULL;
    if (pipe(errfd) != 0) { close(pipefd[0]); close(pipefd[1]); return NULL; }
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        close(errfd[0]); close(errfd[1]);
        return NULL;
    }
    if (pid == 0) {
        close(pipefd[0]);
        close(errfd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(errfd[1], STDERR_FILENO);
        close(pipefd[1]);
        close(errfd[1]);
        execl("/usr/bin/env", "env", "python3", script, audio_path, (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    close(errfd[1]);

    /* Collect both pipes under one deadline.
     *
     * This runs on the poll thread, so a transcriber that never finishes froze
     * every chat until the bot was restarted: there was no timeout here and
     * none in the script. The wait must cover the reads, not just waitpid --
     * a wedged child blocks the parent in read() and waitpid is never reached
     * (measured: SIGALRM fired in read(), the waitpid line was never executed).
     *
     * Draining both descriptors together also removes a deadlock: reading
     * stdout to EOF first meant a child that filled the 64 KB stderr pipe
     * buffer blocked writing, never closed stdout, and hung the parent
     * (measured: OK at 60000 bytes of stderr, hung at 70000). */
    sds text = sdsempty();
    sds err = sdsempty();
    int status = 0;
    int timed_out = 0;
    {
        int fds[2] = { pipefd[0], errfd[0] };
        sds *dst[2] = { &text, &err };
        int open_fds = 2;
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        while (open_fds > 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long elapsed_ms = (now.tv_sec - t0.tv_sec) * 1000 +
                              (now.tv_nsec - t0.tv_nsec) / 1000000;
            long left = ALPHA_VOICE_TIMEOUT_MS - elapsed_ms;
            if (left <= 0) { timed_out = 1; break; }

            struct pollfd pfd[2];
            int np = 0;
            int idx[2];
            for (int i = 0; i < 2; i++) {
                if (fds[i] < 0) continue;
                pfd[np].fd = fds[i];
                pfd[np].events = POLLIN;
                pfd[np].revents = 0;
                idx[np] = i;
                np++;
            }
            int pr = poll(pfd, (nfds_t)np, (int)left);
            if (pr < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (pr == 0) { timed_out = 1; break; }

            for (int k = 0; k < np; k++) {
                if (!(pfd[k].revents & (POLLIN | POLLHUP | POLLERR))) continue;
                char buf[4096];
                ssize_t n = read(pfd[k].fd, buf, sizeof(buf));
                if (n > 0) {
                    *dst[idx[k]] = sdscatlen(*dst[idx[k]], buf, (size_t)n);
                } else {
                    close(pfd[k].fd);
                    fds[idx[k]] = -1;
                    open_fds--;
                }
            }
        }
        for (int i = 0; i < 2; i++) if (fds[i] >= 0) close(fds[i]);
    }

    if (timed_out) {
        fprintf(stderr, "[alpha-tg] transcriber exceeded %ds, killing pid %d\n",
                ALPHA_VOICE_TIMEOUT_MS / 1000, (int)pid);
        kill(pid, SIGKILL);
        /* SIGKILL cannot kill a process stuck in D-state (uninterruptible
         * kernel wait). A blocking waitpid would hang the poll thread forever,
         * so poll with a short grace period and give up if the child is still
         * alive. It will be reaped by launchd when the call returns. */
        {
            int grace = 0;
            while (grace < 20) {  /* 20 * 100ms = 2s grace */
                if (waitpid(pid, &status, WNOHANG) == pid) break;
                usleep(100000);
                grace++;
            }
        }
        sdsfree(text);
        sdsfree(err);
        return NULL;
    }
    /* The normal path: the child exited cleanly, so a blocking waitpid is
     * safe — but a process that was killed by SIGKILL in the timed_out path
     * above may still be in D-state, so use the same poll pattern here too
     * for consistency. */
    {
        int grace = 0;
        while (grace < 20) {  /* 20 * 100ms = 2s grace */
            if (waitpid(pid, &status, WNOHANG) == pid) break;
            usleep(100000);
            grace++;
        }
    }
    sdstrim(text, " \t\r\n");
    sdstrim(err, " \t\r\n");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || sdslen(text) == 0) {
        fprintf(stderr, "[alpha-tg] transcription failed (exit %d): %.300s\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                sdslen(err) ? err : "(no stderr)");
        sdsfree(text);
        sdsfree(err);
        return NULL;
    }
    sdsfree(err);
    return text;
}

/* The one place that decides where sessions live. Both the path builder and
 * the directory creation must agree, so they share this rather than each
 * composing their own -- they used to disagree (paths from the install root,
 * mkdir relative to the cwd) and every session_save silently failed. */
static void session_dir(char *out, size_t outsz) {
    snprintf(out, outsz, "%s/sessions", alpha_install_root());
}

/* Create it, returning 0 on success. */
static int session_dir_ensure(void) {
    char dir[PATH_MAX];
    session_dir(dir, sizeof(dir));
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "[alpha-tg] cannot create %s: %s\n", dir, strerror(errno));
        return -1;
    }
    return 0;
}

/* Refuse to start when another poller is already running.
 *
 * Two instances long-polling one bot token is not an error either of them can
 * see: Telegram hands each update to whichever asked first, so messages
 * disappear at random and the bot merely looks like it ignored you. The shell
 * wrapper guarded this with a pidfile, which (a) does not cover `./alpha
 * --telegram` run directly and (b) was observed holding a pid that had been
 * dead for hours. An flock is held by the kernel and released on exit however
 * the process dies, so it cannot go stale.
 *
 * The lock sits beside tg_offset because that -- with the session files -- is
 * the state two pollers would corrupt. Returns the held fd, or -1. */
static int telegram_lock_acquire(void) {
    char path[PATH_MAX], dir[PATH_MAX];
    session_dir(dir, sizeof(dir));
    snprintf(path, sizeof(path), "%s/telegram.lock", dir);

    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        fprintf(stderr, "[alpha-tg] cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        char who[64] = "";
        ssize_t n = pread(fd, who, sizeof(who) - 1, 0);
        if (n > 0) who[n] = 0;
        fprintf(stderr,
                "[alpha-tg] another poller already holds %s%s%s — refusing to "
                "start a second one\n",
                path, who[0] ? " " : "", who);
        close(fd);
        return -1;
    }
    /* Record who holds it. Advisory only: the flock is the actual guarantee. */
    if (ftruncate(fd, 0) == 0) {
        char line[64];
        int len = snprintf(line, sizeof(line), "pid=%ld", (long)getpid());
        if (pwrite(fd, line, (size_t)len, 0) < 0) { /* diagnostics only */ }
    }
    return fd;
}

/* Keep the log bounded.
 *
 * stderr is redirected to a file by the launcher and nothing ever truncated
 * it: 3000 lines had accumulated, ~95% of them "poll ok". Rotating in here
 * rather than in the wrapper means it also applies to `./alpha --telegram`
 * run directly, and it can happen while the process is live.
 *
 * One generation is kept (.1) so an error just before rotation is still
 * recoverable. Called from the poll loop, which is the only frequent writer.
 * Does nothing when stderr is not a regular file (a terminal, a pipe). */
#ifndef ALPHA_LOG_MAX_BYTES
#define ALPHA_LOG_MAX_BYTES (2 * 1024 * 1024)
#endif

static void log_rotate_if_large(void) {
    struct stat st;
    if (fstat(fileno(stderr), &st) != 0) return;
    if (!S_ISREG(st.st_mode)) return;
    if (st.st_size < ALPHA_LOG_MAX_BYTES) return;

    /* The path stderr points at, not a guess: the launcher's ALPHA_LOG is not
     * visible here, and `./alpha --telegram >foo` uses neither. */
    char path[PATH_MAX];
    if (fcntl(fileno(stderr), F_GETPATH, path) != 0) return;

    char old[PATH_MAX];
    if (snprintf(old, sizeof(old), "%s.1", path) >= (int)sizeof(old)) return;
    if (rename(path, old) != 0) return;

    /* Reopen onto the same fd so the launcher's redirect keeps working and
     * every existing FILE* (including this one) writes to the new file. */
    if (!freopen(path, "a", stderr)) return;
    setvbuf(stderr, NULL, _IOLBF, 0);
    fprintf(stderr, "[alpha-tg] log rotated at %lld bytes -> %s\n",
            (long long)st.st_size, old);
}

static void session_path_for_chat(char *out, size_t outsz, long long chat_id) {
    char dir[PATH_MAX];
    session_dir(dir, sizeof(dir));
    snprintf(out, outsz, "%s/chat_%lld.json", dir, chat_id);
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
    /* Broadcast, not signal: the workers are not interchangeable. The reserved
     * fast-lane worker refuses any job job_is_quick() rejects, so a signal that
     * happens to wake it leaves the job queued with nobody else woken -- the
     * request simply never runs (measured: 3-4 of 25 long jobs lost). */
    pthread_cond_broadcast(&q->cv);
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
    if (session_dir_ensure() != 0) return 1;
    if (telegram_lock_acquire() < 0) return 1;   /* held until the process exits */
    char sess_dir[PATH_MAX], off_path[PATH_MAX];
    session_dir(sess_dir, sizeof(sess_dir));
    snprintf(off_path, sizeof(off_path), "%s/tg_offset", sess_dir);

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
        log_rotate_if_large();
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

            /* A voice note becomes the turn's text.
             *
             * This runs on the poll thread, so polling stalls for the length
             * of the transcription (measured: 7s for a 3s note, 11s for a 15s
             * one, with the medium model). That is accepted: the transcript
             * must exist before the job can be queued, and Telegram's
             * getUpdates simply resumes from the same offset afterwards. What
             * it must not do is stall forever, so voice_transcribe enforces
             * ALPHA_VOICE_TIMEOUT_MS and kills the child past it. */
            sds voice_text = NULL;
            if (!text || !text[0]) {
                cJSON *voice = cJSON_GetObjectItem(msg, "voice");
                if (!voice) voice = cJSON_GetObjectItem(msg, "audio");
                const char *fid = voice ?
                    cJSON_GetStringValue(cJSON_GetObjectItem(voice, "file_id")) : NULL;
                if (fid && fid[0]) {
                    char audio[PATH_MAX];
                    fprintf(stderr, "[alpha-tg] chat=%lld voice note\n", chat_id);
                    if (voice_download(token, fid, audio, sizeof(audio))) {
                        voice_text = voice_transcribe(audio);
                        unlink(audio);
                    }
                    if (!voice_text) {
                        tg_send(token, chat_id,
                                "Could not transcribe that voice message. "
                                "See /tmp/agent-alpha-telegram.log for why.");
                        continue;
                    }
                    fprintf(stderr, "[alpha-tg] transcript: %.80s\n", voice_text);
                    text = voice_text;
                }
            }
            if (!text || !text[0]) continue;

            char spath[PATH_MAX];
            session_path_for_chat(spath, sizeof(spath), chat_id);

            if (strcmp(text, "/start") == 0 || strcmp(text, "/help") == 0) {
                tg_send(token, chat_id,
                    "Agent Alpha — coding agent on Telegram.\n"
                    "Continuous memory in this chat. Tools run unsandboxed.\n\n"
                    "Talk normally, or send a voice note. For code, say what to\n"
                    "change or test.\n"
                    "/status · /cwd <path> · /new (reset memory)\n");
                { if (voice_text) sdsfree(voice_text); continue; }
            }
            if (strcmp(text, "/new") == 0 || strcmp(text, "/clear") == 0) {
                agent_session_clear(spath);
                tg_send(token, chat_id, "Memory cleared. Fresh conversation.");
                fprintf(stderr, "[alpha-tg] chat=%lld cleared\n", chat_id);
                { if (voice_text) sdsfree(voice_text); continue; }
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
                { if (voice_text) sdsfree(voice_text); continue; }
            }
            if (strcmp(text, "/status") == 0 || strcmp(text, "/cwd") == 0) {
                char st_cwd[PATH_MAX];
                if (!chat_cwd_get_copy(chat_id, st_cwd, sizeof(st_cwd)))
                    snprintf(st_cwd, sizeof(st_cwd), "%s", cfg->cwd ? cfg->cwd : ".");
                sds m = sdscatprintf(sdsempty(),
                    "Agent Alpha\n"
                    "model: %s\nbase: %s\ncwd: %s\n"
                    "security: OFF (open tools)\nmemory: %s",
                    cfg->model ? cfg->model : "?",
                    cfg->base_url ? cfg->base_url : "?",
                    st_cwd,
                    spath);
                tg_send(token, chat_id, m);
                sdsfree(m);
                { if (voice_text) sdsfree(voice_text); continue; }
            }

            /* Everything except pure /commands goes through the model so it
             * lands in memory; only a bare ping answers instantly. */
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
                    { if (voice_text) sdsfree(voice_text); continue; }
                }
            }

            fprintf(stderr, "[alpha-tg] chat=%lld: %.80s\n", chat_id, text);
            /* Commit the offset BEFORE handing off: a crash or restart must not
             * make Telegram redeliver and re-execute the same tools. */
            save_offset(off_path, offset);

            /* Hand off to a worker so polling continues immediately.
             * q_push copies the text, so the transcript can be freed here. */
            if (!q_push(&g_queue, chat_id, text))
                tg_send(token, chat_id, "Busy — too many queued requests. Try again shortly.");
            if (voice_text) sdsfree(voice_text);
        }
        save_offset(off_path, offset);
        cJSON_Delete(rootj);
    }
    return 0;
}
