#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);

static cJSON *parse_res(sds res) {
    cJSON *p=cJSON_Parse(res);
    return p;
}

int main(void){
    TEST_BEGIN("string_distance");

    // 1. Levenshtein kitten -> sitting = 3
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"action","levenshtein");
        cJSON_AddStringToObject(args,"a","kitten");
        cJSON_AddStringToObject(args,"b","sitting");
        sds res=tools_run("string_distance",args,".");
        CHECK(res!=NULL,"lev kitten/sitting non-null");
        cJSON *p=parse_res(res);
        CHECK(p!=NULL,"lev valid json");
        if(p) {
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"distance")),3,"lev kitten->sitting =3");
        }
        if(p) cJSON_Delete(p);
        sdsfree(res); cJSON_Delete(args);
    }
    // 2. Levenshtein empty
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"action","levenshtein");
        cJSON_AddStringToObject(args,"a","");
        cJSON_AddStringToObject(args,"b","abc");
        sds res=tools_run("string_distance",args,".");
        cJSON *p=parse_res(res);
        CHECK(p!=NULL,"lev empty valid json");
        if(p) CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"distance")),3,"lev empty->abc=3");
        if(p) cJSON_Delete(p);
        sdsfree(res); cJSON_Delete(args);
    }
    // 3. Levenshtein identical =0
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"action","levenshtein");
        cJSON_AddStringToObject(args,"a","hello");
        cJSON_AddStringToObject(args,"b","hello");
        sds res=tools_run("string_distance",args,".");
        cJSON *p=parse_res(res);
        CHECK(p!=NULL,"lev identical json");
        if(p) CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"distance")),0,"lev identical 0");
        if(p) cJSON_Delete(p);
        sdsfree(res); cJSON_Delete(args);
    }
    // 4. Damerau transposition adjacent =1
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"action","damerau");
        cJSON_AddStringToObject(args,"a","ca");
        cJSON_AddStringToObject(args,"b","ac");
        sds res=tools_run("string_distance",args,".");
        cJSON *p=parse_res(res);
        CHECK(p!=NULL,"damerau json");
        if(p) CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"distance")),1,"damerau ca->ac =1");
        if(p) cJSON_Delete(p);
        sdsfree(res); cJSON_Delete(args);
    }
    // 5. Damerau vs levenshtein: ca->ac lev=2 damerau=1
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"action","levenshtein");
        cJSON_AddStringToObject(args,"a","ca");
        cJSON_AddStringToObject(args,"b","ac");
        sds res=tools_run("string_distance",args,".");
        cJSON *p=parse_res(res);
        CHECK(p!=NULL,"lev ca/ac json");
        if(p) CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"distance")),2,"lev ca->ac=2");
        if(p) cJSON_Delete(p);
        sdsfree(res); cJSON_Delete(args);
    }
    // 6. Hamming equal length
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"action","hamming");
        cJSON_AddStringToObject(args,"a","karolin");
        cJSON_AddStringToObject(args,"b","kathrin");
        sds res=tools_run("string_distance",args,".");
        cJSON *p=parse_res(res);
        CHECK(p!=NULL,"hamming json");
        if(p) CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"distance")),3,"hamming karolin/kathrin=3");
        if(p) cJSON_Delete(p);
        sdsfree(res); cJSON_Delete(args);
    }
    // 7. Hamming mismatch length -> error
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"action","hamming");
        cJSON_AddStringToObject(args,"a","abc");
        cJSON_AddStringToObject(args,"b","ab");
        sds res=tools_run("string_distance",args,".");
        CHECK(res!=NULL,"hamming error non-null");
        CHECK(strstr(res,"ERROR")!=NULL,"hamming unequal length error");
        sdsfree(res); cJSON_Delete(args);
    }
    // 8. LCS
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"action","lcs");
        cJSON_AddStringToObject(args,"a","ABCBDAB");
        cJSON_AddStringToObject(args,"b","BDCABA");
        sds res=tools_run("string_distance",args,".");
        cJSON *p=parse_res(res);
        CHECK(p!=NULL,"lcs json");
        if(p) CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"length")),4,"lcs ABCBDAB/BDCABA=4");
        if(p) cJSON_Delete(p);
        sdsfree(res); cJSON_Delete(args);
    }
    // 9. Jaro identical =1.0
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"action","jaro");
        cJSON_AddStringToObject(args,"a","martha");
        cJSON_AddStringToObject(args,"b","martha");
        sds res=tools_run("string_distance",args,".");
        cJSON *p=parse_res(res);
        CHECK(p!=NULL,"jaro identical json");
        if(p){
            double sim=cJSON_GetNumberValue(cJSON_GetObjectItem(p,"similarity"));
            CHECK(sim>0.999,"jaro identical ~1.0");
        }
        if(p) cJSON_Delete(p);
        sdsfree(res); cJSON_Delete(args);
    }
    // 10. Jaro known pair martha/marhta ~0.944
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"action","jaro");
        cJSON_AddStringToObject(args,"a","MARTHA");
        cJSON_AddStringToObject(args,"b","MARHTA");
        sds res=tools_run("string_distance",args,".");
        cJSON *p=parse_res(res);
        CHECK(p!=NULL,"jaro MARTHA/MARHTA json");
        if(p){
            double sim=cJSON_GetNumberValue(cJSON_GetObjectItem(p,"similarity"));
            CHECK(sim>0.93 && sim<0.96,"jaro MARTHA/MARHTA ~0.944");
        }
        if(p) cJSON_Delete(p);
        sdsfree(res); cJSON_Delete(args);
    }
    // 11. Jaro-Winkler higher than Jaro for common prefix
    {
        cJSON *a1=cJSON_CreateObject();
        cJSON_AddStringToObject(a1,"action","jaro");
        cJSON_AddStringToObject(a1,"a","MyString");
        cJSON_AddStringToObject(a1,"b","MyStrxyz");
        sds r1=tools_run("string_distance",a1,".");
        cJSON *p1=parse_res(r1);
        double j=p1?cJSON_GetNumberValue(cJSON_GetObjectItem(p1,"similarity")):0;
        cJSON *a2=cJSON_CreateObject();
        cJSON_AddStringToObject(a2,"action","jaro_winkler");
        cJSON_AddStringToObject(a2,"a","MyString");
        cJSON_AddStringToObject(a2,"b","MyStrxyz");
        sds r2=tools_run("string_distance",a2,".");
        cJSON *p2=parse_res(r2);
        double jw=p2?cJSON_GetNumberValue(cJSON_GetObjectItem(p2,"similarity")):0;
        CHECK(jw>=j,"jaro_winkler >= jaro for common prefix");
        if(p1) cJSON_Delete(p1); if(p2) cJSON_Delete(p2);
        sdsfree(r1); sdsfree(r2); cJSON_Delete(a1); cJSON_Delete(a2);
    }
    // 12. Fuzzy ranking best match
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"action","fuzzy");
        cJSON_AddStringToObject(args,"query","apple");
        cJSON *cands=cJSON_CreateArray();
        cJSON_AddItemToArray(cands,cJSON_CreateString("aple"));
        cJSON_AddItemToArray(cands,cJSON_CreateString("apply"));
        cJSON_AddItemToArray(cands,cJSON_CreateString("banana"));
        cJSON_AddItemToArray(cands,cJSON_CreateString("applet"));
        cJSON_AddItemToObject(args,"candidates",cands);
        sds res=tools_run("string_distance",args,".");
        cJSON *p=parse_res(res);
        CHECK(p!=NULL,"fuzzy json");
        if(p){
            const char *best=cJSON_GetStringValue(cJSON_GetObjectItem(p,"best"));
            CHECK(best!=NULL,"fuzzy best exists");
            // best should be applet or aple/apply (all close) but not banana
            CHECK(best && strcmp(best,"banana")!=0,"fuzzy best is not banana");
            cJSON *results=cJSON_GetObjectItem(p,"results");
            CHECK(results && cJSON_GetArraySize(results)==4,"fuzzy 4 results");
            // last should be banana (worst)
            cJSON *last=cJSON_GetArrayItem(results,3);
            const char *last_cand=cJSON_GetStringValue(cJSON_GetObjectItem(last,"candidate"));
            CHECK(last_cand && strcmp(last_cand,"banana")==0,"fuzzy worst is banana");
        }
        if(p) cJSON_Delete(p);
        sdsfree(res); cJSON_Delete(args);
    }
    // 13. Fuzzy with metric levenshtein
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"action","fuzzy");
        cJSON_AddStringToObject(args,"query","kitten");
        cJSON_AddStringToObject(args,"metric","levenshtein");
        cJSON *cands=cJSON_CreateArray();
        cJSON_AddItemToArray(cands,cJSON_CreateString("sitting"));
        cJSON_AddItemToArray(cands,cJSON_CreateString("kitten"));
        cJSON_AddItemToArray(cands,cJSON_CreateString("kittens"));
        cJSON_AddItemToObject(args,"candidates",cands);
        sds res=tools_run("string_distance",args,".");
        cJSON *p=parse_res(res);
        CHECK(p!=NULL,"fuzzy lev json");
        if(p){
            const char *best=cJSON_GetStringValue(cJSON_GetObjectItem(p,"best"));
            CHECK(best && strcmp(best,"kitten")==0,"fuzzy lev best is kitten (distance 0)");
        }
        if(p) cJSON_Delete(p);
        sdsfree(res); cJSON_Delete(args);
    }
    // 14. Alias strdist
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"action","levenshtein");
        cJSON_AddStringToObject(args,"a","abc");
        cJSON_AddStringToObject(args,"b","abc");
        sds res=tools_run("strdist",args,".");
        CHECK(res!=NULL,"alias strdist non-null");
        CHECK(strstr(res,"\"distance\":0")!=NULL,"alias strdist works");
        sdsfree(res); cJSON_Delete(args);
    }
    // 15. Alias edit_distance
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"action","hamming");
        cJSON_AddStringToObject(args,"a","1010");
        cJSON_AddStringToObject(args,"b","1001");
        sds res=tools_run("edit_distance",args,".");
        CHECK(res!=NULL,"alias edit_distance non-null");
        cJSON *p=parse_res(res);
        CHECK(p!=NULL,"alias edit_distance json");
        if(p) CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"distance")),2,"alias edit_distance hamming 1010/1001=2");
        if(p) cJSON_Delete(p);
        sdsfree(res); cJSON_Delete(args);
    }

    return test_report("string_distance");
}
