/* tool_git.c — Git working tree diff tool */

#define ALPHA_DIFF_TIMEOUT 15
#define ALPHA_DIFF_MAX_UNTRACKED 50

static int git_run(const char *cwd, char **argv, int argc, sds *out) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        if (cwd && cwd[0]) chdir(cwd);
        const char **args = malloc((size_t)(argc + 1) * sizeof(char *));
        if (!args) _exit(1);
        for (int i = 0; i < argc; i++) args[i] = argv[i];
        args[argc] = NULL;
        execvp("git", (char *const *)args);
        _exit(127);
    }
    close(pipefd[1]);

    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
    *out = sdsempty();
    char buf[8192];
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int status = 0;
    for (;;) {
        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n > 0) *out = sdscatlen(*out, buf, (size_t)n);
        if (waitpid(pid, &status, WNOHANG) == pid) {
            while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
                *out = sdscatlen(*out, buf, (size_t)n);
            break;
        }
        struct timespec t1;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double el = (double)(t1.tv_sec - t0.tv_sec) +
                    (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        if (el > (double)ALPHA_DIFF_TIMEOUT) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            sdsfree(*out);
            *out = NULL;
            close(pipefd[0]);
            return -1;
        }
        usleep(50000);
    }
    close(pipefd[0]);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static sds working_diff(const char *cwd, const char *mode) {
    if (!mode || !mode[0]) mode = "working";
    if (strcmp(mode, "working") != 0 && strcmp(mode, "staged") != 0 &&
        strcmp(mode, "all") != 0)
        return sdscatprintf(sdsempty(),
            "ERROR: unknown mode '%s'. Use: working, staged, all", mode);

    {
        char *argv[] = { "git", "-c", "core.quotePath=false", "rev-parse",
                         "--is-inside-work-tree" };
        sds test_out = NULL;
        int rc = git_run(cwd, argv, 5, &test_out);
        if (test_out) sdsfree(test_out);
        if (rc != 0)
            return sdsnew("ERROR: not a git repository (or git not found)");
    }

    char *diff_args[8];
    int diff_argc = 0;
    diff_args[diff_argc++] = "git";
    diff_args[diff_argc++] = "-c";
    diff_args[diff_argc++] = "core.quotePath=false";
    if (strcmp(mode, "staged") == 0) {
        diff_args[diff_argc++] = "diff";
        diff_args[diff_argc++] = "--cached";
    } else if (strcmp(mode, "all") == 0) {
        diff_args[diff_argc++] = "diff";
        diff_args[diff_argc++] = "HEAD";
    } else {
        diff_args[diff_argc++] = "diff";
    }

    sds stat_out = NULL;
    diff_args[diff_argc++] = "--stat";
    int rc = git_run(cwd, diff_args, diff_argc, &stat_out);
    diff_argc--;
    if (rc != 0 && rc != 1) {
        if (stat_out) sdsfree(stat_out);
        return sdsnew("ERROR: git diff --stat failed");
    }

    sds diff_out = NULL;
    rc = git_run(cwd, diff_args, diff_argc, &diff_out);
    if (rc != 0 && rc != 1) {
        if (stat_out) sdsfree(stat_out);
        if (diff_out) sdsfree(diff_out);
        return sdsnew("ERROR: git diff failed");
    }

    sds untracked_diff = NULL;
    if (strcmp(mode, "working") == 0 || strcmp(mode, "all") == 0) {
        char *ls_args[] = { "git", "-c", "core.quotePath=false",
                            "ls-files", "--others", "--exclude-standard" };
        sds untracked_list = NULL;
        rc = git_run(cwd, ls_args, 5, &untracked_list);
        if (rc == 0 && untracked_list && untracked_list[0]) {
            untracked_diff = sdsempty();
            int count = 0;
            char *save = NULL;
            char *line = strtok_r(untracked_list, "\n", &save);
            while (line && count < ALPHA_DIFF_MAX_UNTRACKED) {
                while (*line == ' ' || *line == '\t') line++;
                if (line[0]) {
                    char *noindex_args[] = {
                        "git", "-c", "core.quotePath=false",
                        "diff", "--no-index", "--", "/dev/null", line
                    };
                    sds file_diff = NULL;
                    git_run(cwd, noindex_args, 8, &file_diff);
                    if (file_diff && file_diff[0]) {
                        untracked_diff = sdscat(untracked_diff, file_diff);
                        if (!strchr(file_diff, '\n') ||
                            file_diff[sdslen(file_diff) - 1] != '\n')
                            untracked_diff = sdscat(untracked_diff, "\n");
                    }
                    if (file_diff) sdsfree(file_diff);
                    count++;
                }
                line = strtok_r(NULL, "\n", &save);
            }
            int remaining = 0;
            while (line) {
                while (*line == ' ' || *line == '\t') line++;
                if (line[0]) remaining++;
                line = strtok_r(NULL, "\n", &save);
            }
            if (remaining > 0)
                untracked_diff = sdscatprintf(untracked_diff,
                    "... (%d more untracked files not shown)\n", remaining);
        }
        if (untracked_list) sdsfree(untracked_list);
    }

    sds result = sdsempty();
    if (stat_out && stat_out[0]) {
        result = sdscat(result, stat_out);
        result = sdscat(result, "\n\n");
    }
    if (diff_out && diff_out[0]) {
        result = sdscat(result, diff_out);
    }
    if (untracked_diff && untracked_diff[0]) {
        if (sdslen(result) > 0 && result[sdslen(result) - 1] != '\n')
            result = sdscat(result, "\n");
        result = sdscat(result, untracked_diff);
    }

    if (stat_out) sdsfree(stat_out);
    if (diff_out) sdsfree(diff_out);
    if (untracked_diff) sdsfree(untracked_diff);

    if (sdslen(result) == 0)
        result = sdscat(result, "(no changes)\n");

    return result;
}

static sds tool_working_diff_run(cJSON *args, const char *cwd) {
    const char *mode = cJSON_GetStringValue(cJSON_GetObjectItem(args, "mode"));
    return working_diff(cwd, mode);
}

static const alpha_tool_t tool_working_diff = {
    .name = "working_diff",
    .aliases = {"diff", NULL},
    .category = "git",
    .description = "Collect a git diff of the working directory. Modes: 'working' (unstaged + untracked, default), 'staged' (git diff --cached), 'all' (everything since HEAD + untracked). Untracked files are shown as new-file diffs via git diff --no-index /dev/null <file>. Returns the diff as text.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"working_diff\",\"description\":\"Collect a git diff of the working directory. Modes: 'working' (unstaged + untracked, default), 'staged' (git diff --cached), 'all' (everything since HEAD + untracked). Untracked files are shown as new-file diffs via git diff --no-index /dev/null <file>. Returns the diff as text.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"mode\":{\"type\":\"string\",\"enum\":[\"working\",\"staged\",\"all\"],\"description\":\"Diff mode: working (default), staged, or all\"}},\"required\":[]}}}",
    .run = tool_working_diff_run
};
