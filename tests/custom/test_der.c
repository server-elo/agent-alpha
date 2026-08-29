/* test_der.c — tests for der (ASN.1 DER structure parser) tool */
#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
static cJSON *P(sds s){ if(!s) return NULL; return cJSON_Parse(s); }
static int is_err(sds r){ return r && strncmp(r,"ERROR:",6)==0; }

int main(void){
    TEST_BEGIN("der");

    /* 1. parse simple SEQUENCE of two INTEGERs (hex) */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"data","3006020101020101");
        sds r=tools_run("der",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"parse SEQUENCE JSON");
        if(p){
            cJSON *root=cJSON_GetObjectItem(p,"root");
            CHECK(root!=NULL,"root present");
            if(root){
                CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(root,"tag")),16,"root tag 16");
                CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(root,"tag_name")),"SEQUENCE")==0,"root tag_name SEQUENCE");
                CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(root,"class")),"universal")==0,"root class universal");
                CHECK(cJSON_IsTrue(cJSON_GetObjectItem(root,"constructed")),"root constructed");
                CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(root,"length")),6,"root length 6");
                CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(root,"total_len")),8,"root total_len 8");
                cJSON *ch=cJSON_GetObjectItem(root,"children");
                CHECK(ch && cJSON_GetArraySize(ch)==2,"two children");
                if(ch && cJSON_GetArraySize(ch)==2){
                    cJSON *c0=cJSON_GetArrayItem(ch,0);
                    CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(c0,"tag")),2,"child tag INTEGER");
                    CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(c0,"value_offset")),4,"child value_offset 4");
                    CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(c0,"value_len")),1,"child value_len 1");
                    CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(c0,"value_hex")),"01")==0,"child value 01");
                }
            }
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 2. same blob as base64 */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","MAYCAQECAQE=");
        cJSON_AddStringToObject(a,"format","base64");
        sds r=tools_run("der",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"base64 parse JSON");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"bytes")),8,"base64 decoded 8 bytes");
            cJSON *root=cJSON_GetObjectItem(p,"root");
            CHECK(root && cJSON_GetObjectItem(root,"tag_name") &&
                  strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(root,"tag_name")),"SEQUENCE")==0,
                  "base64 root SEQUENCE");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 3. auto-detect hex with separators */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","30 06:02 01 01 02 01 01");
        sds r=tools_run("der",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"auto hex with separators");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"format")),"hex")==0,"auto picked hex");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"bytes")),8,"8 bytes");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 4. truncated content -> ERROR */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","30060201");
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"truncated content ERROR");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 5. indefinite length (BER, not DER) -> ERROR */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","30800201010000");
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"indefinite length ERROR");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 6. reserved length 0xFF -> ERROR */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","04FF0000");
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"reserved 0xFF length ERROR");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 7. non-minimal long-form length (< 128) -> ERROR */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","0481054141414141");
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"long-form for short length ERROR");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 8. long-form length with leading zero -> ERROR */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","04820085" /* 133 but leading zero */);
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"leading-zero long-form length ERROR");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 9. trailing bytes after top-level TLV -> ERROR */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","05000500");
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"trailing bytes ERROR");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 10. empty / missing input -> ERROR */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","");
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"empty input ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"missing data ERROR");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 11. invalid hex character with explicit format -> ERROR */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","ZZZZ");
        cJSON_AddStringToObject(a,"format","hex");
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"invalid hex char ERROR");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 12. odd hex digit count -> ERROR */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","300");
        cJSON_AddStringToObject(a,"format","hex");
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"odd hex digits ERROR");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 13. bad base64 (length not multiple of 4) -> ERROR */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","MAYCAQE");
        cJSON_AddStringToObject(a,"format","base64");
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"bad base64 length ERROR");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 14. valid action: good input -> valid true */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","valid");
        cJSON_AddStringToObject(a,"data","3006020101020101");
        sds r=tools_run("der",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid action JSON");
        if(p){ CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"valid")),"valid true"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 15. valid action: malformed input -> valid false, not an ERROR string */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","valid");
        cJSON_AddStringToObject(a,"data","30060201");
        sds r=tools_run("der",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid false still JSON");
        if(p){
            CHECK(cJSON_IsFalse(cJSON_GetObjectItem(p,"valid")),"valid false");
            CHECK(cJSON_GetStringValue(cJSON_GetObjectItem(p,"error"))!=NULL,"error message present");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 16. context-specific constructed tag [0] wrapping INTEGER 1 */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","A003020101");
        sds r=tools_run("der",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"context tag parse");
        if(p){
            cJSON *root=cJSON_GetObjectItem(p,"root");
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(root,"class")),"context-specific")==0,"class context-specific");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(root,"tag")),0,"context tag 0");
            cJSON *ch=cJSON_GetObjectItem(root,"children");
            CHECK(ch && cJSON_GetArraySize(ch)==1,"context child INTEGER");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 17. high-tag-number form: application tag 65, empty content */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","5F4100");
        sds r=tools_run("der",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"high-tag parse");
        if(p){
            cJSON *root=cJSON_GetObjectItem(p,"root");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(root,"tag")),65,"high tag 65");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(root,"header_len")),3,"header_len 3");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(root,"length")),0,"length 0");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 18. high-tag form for tag < 31 (non-minimal DER) -> ERROR */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","5F1E00");
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"non-minimal high-tag ERROR");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 19. truncated high-tag-number -> ERROR */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","5F81");
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"truncated high-tag ERROR");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 20. legitimate long-form length: OCTET STRING of 128 bytes */
    {
        sds hex=sdscatprintf(sdsempty(),"048180");
        for(int i=0;i<128;i++) hex=sdscat(hex,"41");
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data",hex);
        sds r=tools_run("der",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"long-form 128 parse");
        if(p){
            cJSON *root=cJSON_GetObjectItem(p,"root");
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(root,"tag_name")),"OCTET STRING")==0,"OCTET STRING");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(root,"length")),128,"length 128");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(root,"header_len")),3,"header_len 3");
            const char *vh=cJSON_GetStringValue(cJSON_GetObjectItem(root,"value_hex"));
            CHECK(vh && strlen(vh)==64,"value_hex capped at 32 bytes");
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(root,"value_hex_truncated")),"value_hex_truncated set");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a); sdsfree(hex);
    }

    /* 21. max_depth=1 truncates grandchildren on nested SEQUENCE */
    {
        /* outer SEQ { inner SEQ { INT 1, INT 2 } } */
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","30083006020101020102");
        cJSON_AddNumberToObject(a,"max_depth",1);
        sds r=tools_run("der",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"depth-limited parse");
        if(p){
            cJSON *root=cJSON_GetObjectItem(p,"root");
            cJSON *ch=cJSON_GetObjectItem(root,"children");
            CHECK(ch && cJSON_GetArraySize(ch)==1,"root has inner child");
            if(ch && cJSON_GetArraySize(ch)==1){
                cJSON *inner=cJSON_GetArrayItem(ch,0);
                CHECK(cJSON_IsTrue(cJSON_GetObjectItem(inner,"children_truncated")),"inner children_truncated");
                CHECK(cJSON_GetObjectItem(inner,"children")==NULL,"inner children omitted");
            }
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 22. default depth fully expands the same nested SEQUENCE */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","30083006020101020102");
        sds r=tools_run("der",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"full-depth parse");
        if(p){
            cJSON *root=cJSON_GetObjectItem(p,"root");
            cJSON *ch=cJSON_GetObjectItem(root,"children");
            cJSON *inner=ch?cJSON_GetArrayItem(ch,0):NULL;
            cJSON *gch=inner?cJSON_GetObjectItem(inner,"children"):NULL;
            CHECK(gch && cJSON_GetArraySize(gch)==2,"grandchildren expanded");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    /* 23. unknown action -> ERROR */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","explode");
        cJSON_AddStringToObject(a,"data","0500");
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"unknown action ERROR");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 24. out-of-range max_depth -> ERROR */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","0500");
        cJSON_AddNumberToObject(a,"max_depth",1000);
        sds r=tools_run("der",a,NULL);
        CHECK(is_err(r),"max_depth out of range ERROR");
        sdsfree(r); cJSON_Delete(a);
    }

    /* 25. NULL primitive parses: universal tag 5, zero length */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"data","0500");
        sds r=tools_run("der",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"NULL parse");
        if(p){
            cJSON *root=cJSON_GetObjectItem(p,"root");
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(root,"tag_name")),"NULL")==0,"tag_name NULL");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(root,"value_len")),0,"NULL value_len 0");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }

    return test_report("der");
}
