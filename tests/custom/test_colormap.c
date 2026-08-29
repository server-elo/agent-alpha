/* test_colormap.c — tests for colormap tool (datoviz port) */
#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
static cJSON *P(sds s){ if(!s) return NULL; return cJSON_Parse(s); }

/* helper: sample with colormap+t, return hex string (caller frees) or NULL */
static char *hex_of(const char *cm, double t){
    cJSON *a=cJSON_CreateObject();
    cJSON_AddStringToObject(a,"action","sample");
    if(cm) cJSON_AddStringToObject(a,"colormap",cm);
    cJSON_AddNumberToObject(a,"t",t);
    sds r=tools_run("colormap",a,NULL);
    cJSON *p=P(r);
    char *out=NULL;
    const char *h=cJSON_GetStringValue(cJSON_GetObjectItem(p,"hex"));
    if(h) out=strdup(h);
    cJSON_Delete(p); sdsfree(r); cJSON_Delete(a);
    return out;
}

int main(void){
    TEST_BEGIN("colormap");

    /* 1. datoviz midpoint exact: viridis t=0.5 -> stop {33,145,140} */
    {
        char *h=hex_of("viridis",0.5);
        CHECK(h && strcmp(h,"#21918C")==0,"viridis t=0.5 = #21918C");
        free(h);
    }
    /* 2. interpolation between stop 0.00 and 0.25 at t=0.125 -> avg */
    {
        char *h=hex_of("viridis",0.125);
        CHECK(h && strcmp(h,"#402A70")==0,"viridis t=0.125 = #402A70");
        free(h);
    }
    /* 3. clamping below and above */
    {
        char *h=hex_of("viridis",-0.5);
        CHECK(h && strcmp(h,"#440154")==0,"viridis t=-0.5 clamps to #440154");
        free(h);
        h=hex_of("viridis",2.0);
        CHECK(h && strcmp(h,"#FDE725")==0,"viridis t=2.0 clamps to #FDE725");
        free(h);
    }
    /* 4. value/min/max normalization (datoviz scale semantics) */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","sample");
        cJSON_AddStringToObject(a,"colormap","gray");
        cJSON_AddNumberToObject(a,"value",5);
        cJSON_AddNumberToObject(a,"min",0);
        cJSON_AddNumberToObject(a,"max",10);
        sds r=tools_run("colormap",a,NULL);
        cJSON *p=P(r);
        const char *h=cJSON_GetStringValue(cJSON_GetObjectItem(p,"hex"));
        CHECK(h && strcmp(h,"#808080")==0,"gray mid-scale = #808080");
        cJSON_Delete(p); sdsfree(r); cJSON_Delete(a);
    }
    /* 5. custom stops, 3 colors, segment selection */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","sample");
        cJSON *st=cJSON_AddArrayToObject(a,"stops");
        cJSON *s0=cJSON_CreateObject();
        cJSON_AddNumberToObject(s0,"position",0.0);
        cJSON_AddStringToObject(s0,"hex","#000000");
        cJSON_AddItemToArray(st,s0);
        cJSON *s1=cJSON_CreateObject();
        cJSON_AddNumberToObject(s1,"position",0.75);
        cJSON_AddStringToObject(s1,"hex","#FF0000");
        cJSON_AddItemToArray(st,s1);
        cJSON *s2=cJSON_CreateObject();
        cJSON_AddNumberToObject(s2,"position",1.0);
        cJSON_AddStringToObject(s2,"hex","#FFFFFF");
        cJSON_AddItemToArray(st,s2);
        cJSON_AddNumberToObject(a,"t",0.6);
        sds r=tools_run("colormap",a,NULL);
        cJSON *p=P(r);
        const char *h=cJSON_GetStringValue(cJSON_GetObjectItem(p,"hex"));
        /* t=0.6 -> in [0,0.75] segment, u=0.8: r=204, g=b=0 -> #CC0000 (both ends have g=b=0) */
        CHECK(h && strcmp(h,"#CC0000")==0,"custom stops t=0.6 = #CC0000");
        cJSON_Delete(p); sdsfree(r); cJSON_Delete(a);
    }
    /* 6. ramp: 3 colors viridis = endpoints + midpoint */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","ramp");
        cJSON_AddStringToObject(a,"colormap","viridis");
        cJSON_AddNumberToObject(a,"count",3);
        sds r=tools_run("colormap",a,NULL);
        cJSON *p=P(r);
        cJSON *cols=cJSON_GetObjectItem(p,"colors");
        CHECK(cJSON_IsArray(cols)&&cJSON_GetArraySize(cols)==3,"ramp count=3");
        if(cols&&cJSON_GetArraySize(cols)==3){
            const char *c0=cJSON_GetStringValue(cJSON_GetArrayItem(cols,0));
            const char *c1=cJSON_GetStringValue(cJSON_GetArrayItem(cols,1));
            const char *c2=cJSON_GetStringValue(cJSON_GetArrayItem(cols,2));
            CHECK(c0&&strcmp(c0,"#440154")==0,"ramp[0] #440154");
            CHECK(c1&&strcmp(c1,"#21918C")==0,"ramp[1] #21918C");
            CHECK(c2&&strcmp(c2,"#FDE725")==0,"ramp[2] #FDE725");
        }
        cJSON_Delete(p); sdsfree(r); cJSON_Delete(a);
    }
    /* 7. ramp count=1 -> t=0 endpoint */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","ramp");
        cJSON_AddStringToObject(a,"colormap","viridis");
        cJSON_AddNumberToObject(a,"count",1);
        sds r=tools_run("colormap",a,NULL);
        cJSON *p=P(r);
        cJSON *cols=cJSON_GetObjectItem(p,"colors");
        const char *c0=cJSON_IsArray(cols)?cJSON_GetStringValue(cJSON_GetArrayItem(cols,0)):NULL;
        CHECK(c0&&strcmp(c0,"#440154")==0,"ramp count=1 -> #440154");
        cJSON_Delete(p); sdsfree(r); cJSON_Delete(a);
    }
    /* 8. parse hex: full, short, alpha forms */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"hex","#FF8000");
        sds r=tools_run("colormap",a,NULL);
        cJSON *p=P(r);
        CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"r")),255,"parse r 255");
        CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"g")),128,"parse g 128");
        CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"b")),0,"parse b 0");
        CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"a")),255,"parse default a 255");
        cJSON_Delete(p); sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"hex","#F80");
        sds r=tools_run("colormap",a,NULL);
        cJSON *p=P(r);
        CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"g")),136,"short #F80 g=136");
        cJSON_Delete(p); sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"hex","#11223344");
        sds r=tools_run("colormap",a,NULL);
        cJSON *p=P(r);
        CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"a")),68,"#RRGGBBAA a=0x44");
        cJSON_Delete(p); sdsfree(r); cJSON_Delete(a);
    }
    /* 9. to_hex round trip */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","to_hex");
        cJSON_AddNumberToObject(a,"r",1);
        cJSON_AddNumberToObject(a,"g",2);
        cJSON_AddNumberToObject(a,"b",3);
        sds r=tools_run("colormap",a,NULL);
        cJSON *p=P(r);
        const char *h=cJSON_GetStringValue(cJSON_GetObjectItem(p,"hex"));
        CHECK(h && strcmp(h,"#010203")==0,"to_hex #010203");
        cJSON_Delete(p); sdsfree(r); cJSON_Delete(a);
    }
    /* 10. stops dump: turbo has 6 stops starting at 0 */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","stops");
        cJSON_AddStringToObject(a,"colormap","turbo");
        sds r=tools_run("colormap",a,NULL);
        cJSON *p=P(r);
        cJSON *st=cJSON_GetObjectItem(p,"stops");
        CHECK(cJSON_IsArray(st)&&cJSON_GetArraySize(st)==6,"turbo has 6 stops");
        cJSON_Delete(p); sdsfree(r); cJSON_Delete(a);
    }
    /* 11. list contains viridis */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","list");
        sds r=tools_run("colormap",a,NULL);
        cJSON *p=P(r);
        cJSON *arr=cJSON_GetObjectItem(p,"colormaps");
        int found=0;
        if(cJSON_IsArray(arr)){
            cJSON *it;
            cJSON_ArrayForEach(it,arr){
                const char *n=cJSON_GetStringValue(cJSON_GetObjectItem(it,"name"));
                if(n&&strcmp(n,"viridis")==0){found=1;break;}
            }
        }
        CHECK(found,"list contains viridis");
        cJSON_Delete(p); sdsfree(r); cJSON_Delete(a);
    }
    /* --- adversarial negatives --- */
    /* 12. unknown colormap name */
    {
        char *h=hex_of("notacmap",0.5);
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","sample");
        cJSON_AddStringToObject(a,"colormap","notacmap");
        cJSON_AddNumberToObject(a,"t",0.5);
        sds r=tools_run("colormap",a,NULL);
        CHECK(strncmp(r,"ERROR:",6)==0,"unknown colormap -> ERROR");
        CHECK(!h,"no hex for unknown colormap");
        free(h); sdsfree(r); cJSON_Delete(a);
    }
    /* 13. missing t/value -> error, not crash */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","sample");
        cJSON_AddStringToObject(a,"colormap","viridis");
        sds r=tools_run("colormap",a,NULL);
        CHECK(strncmp(r,"ERROR:",6)==0,"sample without t -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 14. max <= min rejected */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","sample");
        cJSON_AddStringToObject(a,"colormap","viridis");
        cJSON_AddNumberToObject(a,"value",1);
        cJSON_AddNumberToObject(a,"min",10);
        cJSON_AddNumberToObject(a,"max",0);
        sds r=tools_run("colormap",a,NULL);
        CHECK(strncmp(r,"ERROR:",6)==0,"max<min -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 15. ramp negative / zero / oversized counts */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","ramp");
        cJSON_AddStringToObject(a,"colormap","viridis");
        cJSON_AddNumberToObject(a,"count",-5);
        sds r=tools_run("colormap",a,NULL);
        CHECK(strncmp(r,"ERROR:",6)==0,"ramp count=-5 -> ERROR");
        sdsfree(r); cJSON_Delete(a);

        a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","ramp");
        cJSON_AddNumberToObject(a,"count",0);
        r=tools_run("colormap",a,NULL);
        CHECK(strncmp(r,"ERROR:",6)==0,"ramp count=0 -> ERROR");
        sdsfree(r); cJSON_Delete(a);

        a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","ramp");
        cJSON_AddNumberToObject(a,"count",5000);
        r=tools_run("colormap",a,NULL);
        CHECK(strncmp(r,"ERROR:",6)==0,"ramp count=5000 -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 16. bad custom stops: too few, bad hex, non-increasing, out of range */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","sample");
        cJSON *st=cJSON_AddArrayToObject(a,"stops");
        cJSON *s0=cJSON_CreateObject();
        cJSON_AddNumberToObject(s0,"position",0.0);
        cJSON_AddStringToObject(s0,"hex","#000000");
        cJSON_AddItemToArray(st,s0);
        sds r=tools_run("colormap",a,NULL);
        CHECK(strncmp(r,"ERROR:",6)==0,"single stop -> ERROR");
        sdsfree(r); cJSON_Delete(a);

        a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","sample");
        st=cJSON_AddArrayToObject(a,"stops");
        s0=cJSON_CreateObject();
        cJSON_AddNumberToObject(s0,"position",0.0);
        cJSON_AddStringToObject(s0,"hex","#GGG");
        cJSON_AddItemToArray(st,s0);
        cJSON *s1=cJSON_CreateObject();
        cJSON_AddNumberToObject(s1,"position",1.0);
        cJSON_AddStringToObject(s1,"hex","#FFFFFF");
        cJSON_AddItemToArray(st,s1);
        r=tools_run("colormap",a,NULL);
        CHECK(strncmp(r,"ERROR:",6)==0,"invalid hex stop -> ERROR");
        sdsfree(r); cJSON_Delete(a);

        a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","sample");
        st=cJSON_AddArrayToObject(a,"stops");
        s0=cJSON_CreateObject();
        cJSON_AddNumberToObject(s0,"position",0.5);
        cJSON_AddStringToObject(s0,"hex","#000000");
        cJSON_AddItemToArray(st,s0);
        s1=cJSON_CreateObject();
        cJSON_AddNumberToObject(s1,"position",0.5);
        cJSON_AddStringToObject(s1,"hex","#FFFFFF");
        cJSON_AddItemToArray(st,s1);
        r=tools_run("colormap",a,NULL);
        CHECK(strncmp(r,"ERROR:",6)==0,"non-increasing positions -> ERROR");
        sdsfree(r); cJSON_Delete(a);

        a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","sample");
        st=cJSON_AddArrayToObject(a,"stops");
        s0=cJSON_CreateObject();
        cJSON_AddNumberToObject(s0,"position",1.5);
        cJSON_AddStringToObject(s0,"hex","#000000");
        cJSON_AddItemToArray(st,s0);
        s1=cJSON_CreateObject();
        cJSON_AddNumberToObject(s1,"position",2.0);
        cJSON_AddStringToObject(s1,"hex","#FFFFFF");
        cJSON_AddItemToArray(st,s1);
        r=tools_run("colormap",a,NULL);
        CHECK(strncmp(r,"ERROR:",6)==0,"positions outside [0,1] -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 17. malformed hex parse inputs */
    {
        const char *bads[]={"FF8000","#12345","#GGGGGG","#","#1234567",""};
        for(int i=0;i<6;i++){
            cJSON *a=cJSON_CreateObject();
            cJSON_AddStringToObject(a,"action","parse");
            cJSON_AddStringToObject(a,"hex",bads[i]);
            sds r=tools_run("colormap",a,NULL);
            CHECK(strncmp(r,"ERROR:",6)==0,"parse bad hex rejected");
            sdsfree(r); cJSON_Delete(a);
        }
    }
    /* 18. to_hex channel out of range and non-integer */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","to_hex");
        cJSON_AddNumberToObject(a,"r",300);
        cJSON_AddNumberToObject(a,"g",0);
        cJSON_AddNumberToObject(a,"b",0);
        sds r=tools_run("colormap",a,NULL);
        CHECK(strncmp(r,"ERROR:",6)==0,"to_hex r=300 -> ERROR");
        sdsfree(r); cJSON_Delete(a);

        a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","to_hex");
        cJSON_AddNumberToObject(a,"r",12.5);
        cJSON_AddNumberToObject(a,"g",0);
        cJSON_AddNumberToObject(a,"b",0);
        r=tools_run("colormap",a,NULL);
        CHECK(strncmp(r,"ERROR:",6)==0,"to_hex r=12.5 -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 19. unknown action */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","frobnicate");
        sds r=tools_run("colormap",a,NULL);
        CHECK(strncmp(r,"ERROR:",6)==0,"unknown action -> ERROR");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 20. schema registration */
    {
        cJSON *schema=tools_schema();
        int found=0;
        int n=cJSON_GetArraySize(schema);
        for(int i=0;i<n;i++){
            cJSON *item=cJSON_GetArrayItem(schema,i);
            cJSON *func=cJSON_GetObjectItem(item,"function");
            if(!func) func=item;
            cJSON *nm=cJSON_GetObjectItem(func,"name");
            if(nm && cJSON_IsString(nm) && strcmp(nm->valuestring,"colormap")==0) found=1;
        }
        CHECK(found,"schema contains colormap");
        cJSON_Delete(schema);
    }

    return test_report("colormap");
}
