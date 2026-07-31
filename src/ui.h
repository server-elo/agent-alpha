#ifndef ALPHA_UI_H
#define ALPHA_UI_H

#include "../deps/sds.h"

#define UI_RESET  "\033[0m"
#define UI_DIM    "\033[2m"
#define UI_BOLD   "\033[1m"
#define UI_RED    "\033[31m"
#define UI_GREEN  "\033[32m"
#define UI_YELLOW "\033[33m"
#define UI_BLUE   "\033[34m"
#define UI_MAGENTA "\033[35m"
#define UI_CYAN   "\033[36m"

int ui_is_tty(void);
int ui_use_color(void);
const char *ui_c(const char *code);     /* the code, or "" when colour is off */
int ui_width(void);
size_t ui_display_width(const char *s);
sds ui_ellipsize(const char *s, size_t max_cols);

void ui_spin_start(const char *label);
void ui_spin_label(const char *label);
void ui_spin_stop(void);
void ui_spin_shutdown(void);

void ui_rule(const char *title);
void ui_status(const char *label, const char *value);
void ui_error(const char *msg);
void ui_note(const char *msg);

#endif
