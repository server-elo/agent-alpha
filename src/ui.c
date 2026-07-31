/* Terminal front end.
 *
 * Everything here degrades to plain text when stdout is not a tty, because the
 * REPL is also used from scripts and pipes: colour codes and spinner frames in
 * a log file are noise, and a spinner writing to a pipe with no reader blocks. */
#include "alpha.h"
#include "ui.h"
#include <sys/ioctl.h>
#include <termios.h>

static int ui_color = -1;      /* lazily resolved */

int ui_is_tty(void) {
    return isatty(STDOUT_FILENO);
}

/* NO_COLOR is respected (https://no-color.org): users pipe this into tools. */
int ui_use_color(void) {
    if (ui_color < 0) {
        const char *nc = getenv("NO_COLOR");
        const char *term = getenv("TERM");
        ui_color = ui_is_tty()
                && !(nc && nc[0] != 0)
                && !(term && strcmp(term, "dumb") == 0);
    }
    return ui_color;
}

const char *ui_c(const char *code) {
    return ui_use_color() ? code : "";
}

int ui_width(void) {
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 20) return w.ws_col;
    const char *cols = getenv("COLUMNS");
    if (cols && cols[0]) {
        int c = atoi(cols);
        if (c > 20) return c;
    }
    return 80;
}

/* --- display width ---------------------------------------------------------
 *
 * Padding by strlen() breaks on any non-ASCII text: "grün" is 5 bytes but 4
 * columns, so every box drawn around non-English output came out ragged. Count
 * characters, and treat the CJK/emoji ranges as double width. */
size_t ui_display_width(const char *s) {
    size_t w = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; ) {
        unsigned cp;
        int len;
        if (*p < 0x80)            { cp = *p; len = 1; }
        else if ((*p & 0xE0) == 0xC0) { cp = *p & 0x1F; len = 2; }
        else if ((*p & 0xF0) == 0xE0) { cp = *p & 0x0F; len = 3; }
        else if ((*p & 0xF8) == 0xF0) { cp = *p & 0x07; len = 4; }
        else { p++; continue; }                 /* stray continuation byte */
        for (int i = 1; i < len; i++) {
            if ((p[i] & 0xC0) != 0x80) { len = i; break; }
            cp = (cp << 6) | (p[i] & 0x3F);
        }
        p += len;
        if (cp == 0x200B || (cp >= 0x0300 && cp <= 0x036F)) continue;  /* zero width */
        if ((cp >= 0x1100 && cp <= 0x115F) || (cp >= 0x2E80 && cp <= 0xA4CF) ||
            (cp >= 0xAC00 && cp <= 0xD7A3) || (cp >= 0xF900 && cp <= 0xFAFF) ||
            (cp >= 0xFF00 && cp <= 0xFF60) || (cp >= 0x1F300 && cp <= 0x1FAFF))
            w += 2;
        else
            w += 1;
    }
    return w;
}

/* --- spinner ---------------------------------------------------------------
 *
 * Runs on its own thread so it keeps moving while the main thread blocks in
 * curl. It must never write once real output has started, or the two interleave
 * mid-line; ui_spin_stop() clears the line and joins before anything else
 * prints. */
typedef struct {
    pthread_t th;
    volatile int running;
    volatile int active;
    char label[128];
    time_t start;
    pthread_mutex_t lock;
} ui_spinner_t;

static ui_spinner_t g_spin = { .lock = PTHREAD_MUTEX_INITIALIZER };

static const char *SPIN_FRAMES[] = {
    "\u28cb", "\u28d9", "\u28f8", "\u28f4", "\u28e6", "\u28c7", "\u288f", "\u282f",
    "\u289f", "\u28bb"
};
#define SPIN_NFRAMES ((int)(sizeof(SPIN_FRAMES) / sizeof(SPIN_FRAMES[0])))

static void *spin_thread(void *ud) {
    ui_spinner_t *s = ud;
    int i = 0;
    while (s->running) {
        pthread_mutex_lock(&s->lock);
        if (s->active) {
            int secs = (int)(time(NULL) - s->start);
            /* \r + clear-to-EOL, so a shrinking label leaves no debris. */
            printf("\r\033[2K%s%s%s %s %s(%ds, esc to interrupt)%s",
                   ui_c(UI_CYAN), SPIN_FRAMES[i % SPIN_NFRAMES], ui_c(UI_RESET),
                   s->label, ui_c(UI_DIM), secs, ui_c(UI_RESET));
            fflush(stdout);
        }
        pthread_mutex_unlock(&s->lock);
        i++;
        usleep(90000);
    }
    return NULL;
}

void ui_spin_start(const char *label) {
    if (!ui_is_tty()) return;
    pthread_mutex_lock(&g_spin.lock);
    snprintf(g_spin.label, sizeof(g_spin.label), "%s", label ? label : "working");
    g_spin.start = time(NULL);
    g_spin.active = 1;
    int need_thread = !g_spin.running;
    if (need_thread) g_spin.running = 1;
    pthread_mutex_unlock(&g_spin.lock);
    if (need_thread && pthread_create(&g_spin.th, NULL, spin_thread, &g_spin) != 0)
        g_spin.running = 0;      /* no spinner is fine; a crash is not */
}

void ui_spin_label(const char *label) {
    if (!ui_is_tty()) return;
    pthread_mutex_lock(&g_spin.lock);
    snprintf(g_spin.label, sizeof(g_spin.label), "%s", label ? label : "working");
    pthread_mutex_unlock(&g_spin.lock);
}

/* Pause the spinner and clear its line. Safe to call when not running. */
void ui_spin_stop(void) {
    if (!ui_is_tty()) return;
    pthread_mutex_lock(&g_spin.lock);
    int was = g_spin.active;
    g_spin.active = 0;
    if (was) {
        printf("\r\033[2K");
        fflush(stdout);
    }
    pthread_mutex_unlock(&g_spin.lock);
}

void ui_spin_shutdown(void) {
    if (!g_spin.running) return;
    ui_spin_stop();
    g_spin.running = 0;
    pthread_join(g_spin.th, NULL);
}

/* --- output ---------------------------------------------------------------- */

void ui_rule(const char *title) {
    int w = ui_width();
    if (!title || !title[0]) {
        printf("%s", ui_c(UI_DIM));
        for (int i = 0; i < w; i++) printf("\u2500");
        printf("%s\n", ui_c(UI_RESET));
        return;
    }
    int tw = (int)ui_display_width(title) + 2;
    printf("%s\u2500\u2500 %s %s", ui_c(UI_DIM), title, ui_c(UI_RESET));
    printf("%s", ui_c(UI_DIM));
    for (int i = tw + 4; i < w; i++) printf("\u2500");
    printf("%s\n", ui_c(UI_RESET));
}

void ui_status(const char *label, const char *value) {
    printf("  %s%-10s%s %s\n", ui_c(UI_DIM), label, ui_c(UI_RESET), value ? value : "");
}

void ui_error(const char *msg) {
    ui_spin_stop();
    printf("%s%s%s %s\n", ui_c(UI_RED), "\u2717", ui_c(UI_RESET), msg ? msg : "");
    fflush(stdout);
}

void ui_note(const char *msg) {
    ui_spin_stop();
    printf("%s%s%s\n", ui_c(UI_DIM), msg ? msg : "", ui_c(UI_RESET));
    fflush(stdout);
}

/* Shorten a single-line preview to fit, cutting on a character boundary so a
 * multi-byte character is never split across the ellipsis. */
sds ui_ellipsize(const char *s, size_t max_cols) {
    sds out = sdsempty();
    if (!s) return out;
    /* Collapse whitespace: tool arguments are JSON with embedded newlines, and
     * a raw one would break the single-line layout. */
    sds flat = sdsempty();
    int sp = 0;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '\n' || c == '\r' || c == '\t' || c == ' ') {
            if (!sp && sdslen(flat)) { flat = sdscat(flat, " "); sp = 1; }
        } else {
            sp = 0;
            flat = sdscatlen(flat, p, 1);
        }
    }
    if (ui_display_width(flat) <= max_cols) return flat;

    size_t cols = 0, i = 0;
    while (flat[i] && cols < max_cols - 1) {
        size_t start = i;
        unsigned char c = (unsigned char)flat[i];
        int len = c < 0x80 ? 1 : (c & 0xE0) == 0xC0 ? 2 : (c & 0xF0) == 0xE0 ? 3
                : (c & 0xF8) == 0xF0 ? 4 : 1;
        if (i + (size_t)len > sdslen(flat)) break;
        i += (size_t)len;
        sds ch = sdsnewlen(flat + start, (size_t)len);
        cols += ui_display_width(ch);
        sdsfree(ch);
    }
    out = sdscatlen(out, flat, i);
    out = sdscat(out, "\u2026");
    sdsfree(flat);
    return out;
}
