/* tool_string_distance.c — String Distance & Similarity Suite (pure C)
 * Algorithms: Levenshtein (Wagner-Fischer), Damerau-Levenshtein (OSA),
 * Hamming, LCS (DP), Jaro, Jaro-Winkler, and fuzzy ranking.
 * All operate on raw bytes (UTF-8 safe for ASCII subset); no I/O.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <math.h>

#define SD_MAX_LEN 4096

static int sd_min3(int a, int b, int c) {
    int m = a < b ? a : b;
    return m < c ? m : c;
}

/* Levenshtein distance, two-row DP, O(min(n,m)) space */
static int sd_levenshtein(const char *a, size_t na, const char *b, size_t nb) {
    if (na == 0) return (int)nb;
    if (nb == 0) return (int)na;
    /* make b the shorter to reduce memory */
    if (nb > na) {
        const char *ta = a; size_t tna = na;
        a = b; na = nb;
        b = ta; nb = tna;
    }
    int *prev = (int*)malloc((nb+1)*sizeof(int));
    int *cur  = (int*)malloc((nb+1)*sizeof(int));
    if (!prev || !cur) { free(prev); free(cur); return -1; }
    for (size_t j=0;j<=nb;j++) prev[j]=(int)j;
    for (size_t i=1;i<=na;i++) {
        cur[0]=(int)i;
        for (size_t j=1;j<=nb;j++) {
            int cost = (a[i-1]==b[j-1])?0:1;
            int del = prev[j]+1;
            int ins = cur[j-1]+1;
            int sub = prev[j-1]+cost;
            cur[j]=sd_min3(del,ins,sub);
        }
        int *tmp=prev; prev=cur; cur=tmp;
    }
    int res=prev[nb];
    free(prev); free(cur);
    return res;
}

/* Damerau-Levenshtein OSA (adjacent transposition counts as 1) */
static int sd_damerau(const char *a, size_t na, const char *b, size_t nb) {
    if (na==0) return (int)nb;
    if (nb==0) return (int)na;
    size_t rows=na+1, cols=nb+1;
    int *d=(int*)malloc(rows*cols*sizeof(int));
    if(!d) return -1;
#define D(i,j) d[(i)*cols+(j)]
    for(size_t i=0;i<=na;i++) D(i,0)=(int)i;
    for(size_t j=0;j<=nb;j++) D(0,j)=(int)j;
    for(size_t i=1;i<=na;i++){
        for(size_t j=1;j<=nb;j++){
            int cost=(a[i-1]==b[j-1])?0:1;
            int v=sd_min3(D(i-1,j)+1, D(i,j-1)+1, D(i-1,j-1)+cost);
            if(i>1 && j>1 && a[i-1]==b[j-2] && a[i-2]==b[j-1]){
                int transp=D(i-2,j-2)+1;
                if(transp<v) v=transp;
            }
            D(i,j)=v;
        }
    }
    int res=D(na,nb);
    free(d);
#undef D
    return res;
}

static int sd_hamming(const char *a, size_t na, const char *b, size_t nb) {
    if (na!=nb) return -1;
    int d=0;
    for(size_t i=0;i<na;i++) if(a[i]!=b[i]) d++;
    return d;
}

static int sd_lcs(const char *a, size_t na, const char *b, size_t nb) {
    if(na==0||nb==0) return 0;
    if(nb>na){ const char*ta=a; size_t tna=na; a=b; na=nb; b=ta; nb=tna; }
    int *prev=(int*)calloc(nb+1,sizeof(int));
    int *cur=(int*)calloc(nb+1,sizeof(int));
    if(!prev||!cur){ free(prev); free(cur); return -1; }
    for(size_t i=1;i<=na;i++){
        for(size_t j=1;j<=nb;j++){
            if(a[i-1]==b[j-1]) cur[j]=prev[j-1]+1;
            else cur[j]= prev[j] > cur[j-1] ? prev[j] : cur[j-1];
        }
        int*tmp=prev; prev=cur; cur=tmp;
    }
    int res=prev[nb];
    free(prev); free(cur);
    return res;
}

static double sd_jaro(const char *s1, size_t n1, const char *s2, size_t n2) {
    if(n1==0 && n2==0) return 1.0;
    if(n1==0 || n2==0) return 0.0;
    if(n1==n2 && memcmp(s1,s2,n1)==0) return 1.0;
    size_t match_dist = (n1>n2?n1:n2)/2;
    if(match_dist>0) match_dist--;
    char *m1=(char*)calloc(n1,1);
    char *m2=(char*)calloc(n2,1);
    if(!m1||!m2){ free(m1); free(m2); return 0.0; }
    size_t matches=0;
    for(size_t i=0;i<n1;i++){
        size_t start = i>match_dist?i-match_dist:0;
        size_t end = i+match_dist+1 < n2 ? i+match_dist+1 : n2;
        for(size_t j=start;j<end;j++){
            if(m2[j]) continue;
            if(s1[i]!=s2[j]) continue;
            m1[i]=1; m2[j]=1; matches++; break;
        }
    }
    if(matches==0){ free(m1); free(m2); return 0.0; }
    size_t trans=0;
    size_t k=0;
    for(size_t i=0;i<n1;i++){
        if(!m1[i]) continue;
        while(!m2[k]) k++;
        if(s1[i]!=s2[k]) trans++;
        k++;
    }
    free(m1); free(m2);
    double t = trans/2.0;
    return ((double)matches/n1 + (double)matches/n2 + ((double)matches - t)/matches)/3.0;
}

static double sd_jaro_winkler(const char *s1, size_t n1, const char *s2, size_t n2) {
    double j=sd_jaro(s1,n1,s2,n2);
    if(j==0.0 || j==1.0) return j;
    size_t prefix=0;
    size_t max_pre= n1<n2?n1:n2;
    if(max_pre>4) max_pre=4;
    for(size_t i=0;i<max_pre;i++) if(s1[i]==s2[i]) prefix++; else break;
    return j + prefix*0.1*(1.0 - j);
}

static const char *sd_get_str(cJSON *args, const char *k1, const char *k2, const char *k3) {
    const char *v=NULL;
    if(k1) v=cJSON_GetStringValue(cJSON_GetObjectItem(args,k1));
    if(!v && k2) v=cJSON_GetStringValue(cJSON_GetObjectItem(args,k2));
    if(!v && k3) v=cJSON_GetStringValue(cJSON_GetObjectItem(args,k3));
    return v;
}

static sds tool_string_distance_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action=cJSON_GetStringValue(cJSON_GetObjectItem(args,"action"));
    if(!action||!action[0]) action="levenshtein";

    /* fuzzy_rank is special: needs query + candidates array */
    if(strcmp(action,"fuzzy")==0 || strcmp(action,"fuzzy_rank")==0 || strcmp(action,"rank")==0){
        const char *query=sd_get_str(args,"query","q","text");
        if(!query) query=sd_get_str(args,"a","s1",NULL);
        if(!query) return sdsnew("ERROR: 'query' (or 'a') required for fuzzy ranking");
        cJSON *cands=cJSON_GetObjectItem(args,"candidates");
        if(!cands) cands=cJSON_GetObjectItem(args,"items");
        if(!cands) cands=cJSON_GetObjectItem(args,"list");
        /* also allow JSON string of array in "data" or "b" */
        cJSON *parsed_tmp=NULL;
        if(!cands || !cJSON_IsArray(cands)){
            const char *data_s=cJSON_GetStringValue(cJSON_GetObjectItem(args,"data"));
            if(!data_s) data_s=cJSON_GetStringValue(cJSON_GetObjectItem(args,"b"));
            if(data_s){
                parsed_tmp=cJSON_Parse(data_s);
                if(parsed_tmp && cJSON_IsArray(parsed_tmp)) cands=parsed_tmp;
            }
        }
        if(!cands || !cJSON_IsArray(cands)){
            if(parsed_tmp) cJSON_Delete(parsed_tmp);
            return sdsnew("ERROR: 'candidates' array required for fuzzy (provide JSON array)");
        }
        int n=cJSON_GetArraySize(cands);
        if(n==0){ if(parsed_tmp) cJSON_Delete(parsed_tmp); return sdsnew("ERROR: candidates array empty"); }
        if(n>256) n=256;
        const char *metric_s=cJSON_GetStringValue(cJSON_GetObjectItem(args,"metric"));
        if(!metric_s) metric_s="jaro_winkler";
        int use_lev=(strcmp(metric_s,"levenshtein")==0 || strcmp(metric_s,"lev")==0);
        // build scored list
        struct { const char *s; double score; int dist; } *items=(void*)malloc(sizeof(*items)* (size_t)n);
        if(!items){ if(parsed_tmp) cJSON_Delete(parsed_tmp); return sdsnew("ERROR: alloc failed"); }
        for(int i=0;i<n;i++){
            cJSON *el=cJSON_GetArrayItem(cands,i);
            const char *cs=cJSON_IsString(el)?el->valuestring:"";
            items[i].s=cs;
            if(use_lev){
                int d=sd_levenshtein(query,strlen(query),cs,strlen(cs));
                items[i].dist=d;
                size_t maxl=strlen(query)>strlen(cs)?strlen(query):strlen(cs);
                items[i].score = maxl?1.0 - (double)d/(double)maxl : 1.0;
            } else {
                double jw=sd_jaro_winkler(query,strlen(query),cs,strlen(cs));
                items[i].score=jw;
                items[i].dist=sd_levenshtein(query,strlen(query),cs,strlen(cs));
            }
        }
        // simple insertion sort descending by score
        for(int i=1;i<n;i++){
            int j=i;
            while(j>0 && items[j].score > items[j-1].score){
                __typeof__(items[0]) tmp=items[j];
                items[j]=items[j-1];
                items[j-1]=tmp;
                j--;
            }
        }
        cJSON *out=cJSON_CreateObject();
        cJSON_AddStringToObject(out,"action","fuzzy_rank");
        cJSON_AddStringToObject(out,"query",query);
        cJSON_AddStringToObject(out,"metric",use_lev?"levenshtein":"jaro_winkler");
        cJSON *arr=cJSON_CreateArray();
        for(int i=0;i<n;i++){
            cJSON *o=cJSON_CreateObject();
            cJSON_AddStringToObject(o,"candidate",items[i].s);
            cJSON_AddNumberToObject(o,"score",items[i].score);
            cJSON_AddNumberToObject(o,"levenshtein", (double)items[i].dist);
            cJSON_AddItemToArray(arr,o);
        }
        cJSON_AddItemToObject(out,"results",arr);
        cJSON_AddStringToObject(out,"best",items[0].s);
        char *js=cJSON_PrintUnformatted(out);
        sds res=sdsnew(js?js:"{}");
        free(js); cJSON_Delete(out); free(items);
        if(parsed_tmp) cJSON_Delete(parsed_tmp);
        return res;
    }

    const char *a=sd_get_str(args,"a","s1","text");
    const char *b=sd_get_str(args,"b","s2","candidate");
    if(!a) a="";
    if(!b) {
        const char *data=cJSON_GetStringValue(cJSON_GetObjectItem(args,"data"));
        if(data) b=data;
        else b="";
    }
    size_t na=strlen(a), nb=strlen(b);
    if(na>SD_MAX_LEN || nb>SD_MAX_LEN)
        return sdscatprintf(sdsempty(),"ERROR: input too long (max %d chars each, got %zu and %zu)",SD_MAX_LEN,na,nb);

    if(strcmp(action,"levenshtein")==0 || strcmp(action,"lev")==0){
        int d=sd_levenshtein(a,na,b,nb);
        if(d<0) return sdsnew("ERROR: alloc failed");
        size_t maxl=na>nb?na:nb;
        double sim = maxl? 1.0 - (double)d/(double)maxl : 1.0;
        return sdscatprintf(sdsempty(),
            "{\"action\":\"levenshtein\",\"a\":\"%s\",\"b\":\"%s\",\"distance\":%d,\"max_len\":%zu,\"similarity\":%.6f}",
            a,b,d,maxl,sim);
    }
    if(strcmp(action,"damerau")==0 || strcmp(action,"damerau_levenshtein")==0 || strcmp(action,"dl")==0){
        int d=sd_damerau(a,na,b,nb);
        if(d<0) return sdsnew("ERROR: alloc failed");
        size_t maxl=na>nb?na:nb;
        double sim = maxl? 1.0 - (double)d/(double)maxl : 1.0;
        return sdscatprintf(sdsempty(),
            "{\"action\":\"damerau\",\"a\":\"%s\",\"b\":\"%s\",\"distance\":%d,\"max_len\":%zu,\"similarity\":%.6f}",
            a,b,d,maxl,sim);
    }
    if(strcmp(action,"hamming")==0){
        int d=sd_hamming(a,na,b,nb);
        if(d==-1) return sdscatprintf(sdsempty(),"ERROR: hamming requires equal length (got %zu and %zu)",na,nb);
        double sim = na? 1.0 - (double)d/(double)na : 1.0;
        return sdscatprintf(sdsempty(),
            "{\"action\":\"hamming\",\"a\":\"%s\",\"b\":\"%s\",\"distance\":%d,\"length\":%zu,\"similarity\":%.6f}",
            a,b,d,na,sim);
    }
    if(strcmp(action,"lcs")==0 || strcmp(action,"longest_common_subsequence")==0){
        int l=sd_lcs(a,na,b,nb);
        if(l<0) return sdsnew("ERROR: alloc failed");
        return sdscatprintf(sdsempty(),
            "{\"action\":\"lcs\",\"a\":\"%s\",\"b\":\"%s\",\"length\":%d,\"a_len\":%zu,\"b_len\":%zu}",
            a,b,l,na,nb);
    }
    if(strcmp(action,"jaro")==0){
        double j=sd_jaro(a,na,b,nb);
        return sdscatprintf(sdsempty(),
            "{\"action\":\"jaro\",\"a\":\"%s\",\"b\":\"%s\",\"similarity\":%.6f,\"distance\":%.6f}",
            a,b,j,1.0-j);
    }
    if(strcmp(action,"jaro_winkler")==0 || strcmp(action,"jaro-winkler")==0 || strcmp(action,"jw")==0){
        double jw=sd_jaro_winkler(a,na,b,nb);
        double j=sd_jaro(a,na,b,nb);
        return sdscatprintf(sdsempty(),
            "{\"action\":\"jaro_winkler\",\"a\":\"%s\",\"b\":\"%s\",\"similarity\":%.6f,\"jaro\":%.6f,\"distance\":%.6f}",
            a,b,jw,j,1.0-jw);
    }
    return sdscatprintf(sdsempty(),"ERROR: unknown string_distance action '%s' (use levenshtein/damerau/hamming/lcs/jaro/jaro_winkler/fuzzy)",action);
}

static const alpha_tool_t tool_string_distance = {
    .name = "string_distance",
    .aliases = {"strdist", "edit_distance", "fuzzy_match", NULL},
    .category = "text",
    .description = "String distance & similarity suite (pure C): Levenshtein, Damerau-Levenshtein (OSA), Hamming, LCS, Jaro, Jaro-Winkler, and fuzzy ranking over candidate lists.",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"string_distance\",\"description\":\"String distance & similarity suite (pure C): Levenshtein, Damerau-Levenshtein (OSA), Hamming, LCS, Jaro, Jaro-Winkler, and fuzzy ranking over candidate lists.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"levenshtein\",\"damerau\",\"hamming\",\"lcs\",\"jaro\",\"jaro_winkler\",\"fuzzy\"],\"description\":\"Distance/similarity algorithm\"},\"a\":{\"type\":\"string\",\"description\":\"First string\"},\"b\":{\"type\":\"string\",\"description\":\"Second string\"},\"query\":{\"type\":\"string\",\"description\":\"Query for fuzzy ranking\"},\"candidates\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},\"description\":\"Candidate strings for fuzzy ranking\"},\"metric\":{\"type\":\"string\",\"enum\":[\"jaro_winkler\",\"levenshtein\"],\"description\":\"Ranking metric for fuzzy\"}},\"required\":[]}}}",
    .run = tool_string_distance_run
};
