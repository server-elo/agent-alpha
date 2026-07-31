#include "../src/agent_loop.c"
static size_t wire_bytes(cJSON *m){ char *s=cJSON_PrintUnformatted(m); size_t n=strlen(s); free(s); return n; }
int main(void){
    cJSON *msgs = cJSON_CreateArray();
    messages_add_text(msgs,"system","sys");
    /* 12 assistant turns each carrying a big write_file tool_call */
    for (int i=0;i<12;i++){
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"role","assistant");
        cJSON_AddStringToObject(a,"content","");
        cJSON *tcs=cJSON_CreateArray();
        cJSON *tc=cJSON_CreateObject();
        cJSON_AddStringToObject(tc,"id","call_x");
        cJSON *fn=cJSON_CreateObject();
        cJSON_AddStringToObject(fn,"name","write_file");
        char *big=malloc(300001); memset(big,'A',300000); big[300000]=0;
        cJSON_AddStringToObject(fn,"arguments",big); free(big);
        cJSON_AddItemToObject(tc,"function",fn);
        cJSON_AddItemToArray(tcs,tc);
        cJSON_AddItemToObject(a,"tool_calls",tcs);
        cJSON_AddItemToArray(msgs,a);
        cJSON *tr=cJSON_CreateObject();
        cJSON_AddStringToObject(tr,"role","tool");
        cJSON_AddStringToObject(tr,"tool_call_id","call_x");
        cJSON_AddStringToObject(tr,"content","ok");
        cJSON_AddItemToArray(msgs,tr);
    }
    printf("budget          = %d bytes\n", ALPHA_LIVE_MAX_BYTES);
    printf("counted before  = %zu\n", messages_bytes(msgs));
    printf("ACTUAL wire before = %zu\n", wire_bytes(msgs));
    trim_live_messages(msgs);
    printf("counted after   = %zu\n", messages_bytes(msgs));
    printf("ACTUAL wire after  = %zu\n", wire_bytes(msgs));
    return 0;
}
