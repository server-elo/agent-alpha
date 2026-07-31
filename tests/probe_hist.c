#include "../src/agent_loop.c"
int main(void){
    /* history_bytes / session_save use the same content-only accounting */
    cJSON *h = cJSON_CreateArray();
    for (int i=0;i<5;i++){
        messages_add_text(h,"user","hi");
        char *big=malloc(300001); memset(big,'B',300000); big[300000]=0;
        messages_add_text(h,"assistant",big); free(big);
    }
    printf("history counted = %zu (cap %d)\n", history_bytes(h), ALPHA_HISTORY_MAX_BYTES);
    session_save("/tmp/probe_hist.json", h);
    struct stat st; stat("/tmp/probe_hist.json",&st);
    printf("saved file      = %lld bytes, msgs left = %d\n",(long long)st.st_size, cJSON_GetArraySize(h));
    return 0;
}
