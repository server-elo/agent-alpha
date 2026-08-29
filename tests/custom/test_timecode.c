/* test_timecode.c — tests for timecode (frame/seconds/SMPTE engine) tool */
#include "alpha.h"
#include "test_util.h"
#include <math.h>

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
static cJSON *P(sds s){ if(!s) return NULL; return cJSON_Parse(s); }
static int IS_ERR(sds r){ return r && strncmp(r,"ERROR",5)==0; }
static int close_enough(double a, double b){ return fabs(a-b) < 1e-6; }

int main(void){
    TEST_BEGIN("timecode");

    /* 1. tc_parse drop-frame 01:02:03;23 @ 29.97 */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","tc_parse");
        cJSON_AddStringToObject(a,"timecode","01:02:03;23");
        cJSON_AddStringToObject(a,"fps","29.97");
        sds r=tools_run("timecode",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"tc_parse parses");
        if(p){
            CHECK(cJSON_IsTrue(cJSON_GetObjectItem(p,"drop")),"drop detected");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"frames")),111601,"frames 111601");
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"nominal_fps")),30,"nominal 30fps");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 2. tc_format round trip in drop mode */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","tc_format");
        cJSON_AddNumberToObject(a,"frames",4142);
        cJSON_AddStringToObject(a,"fps","29.97");
        cJSON_AddBoolToObject(a,"drop",1);
        sds r=tools_run("timecode",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"tc_format drop parses");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"timecode")),"00:02:18;06")==0,"drop uses ; separator");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 3. frame2sec 30 @ 25fps = 1.2s */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","frame2sec");
        cJSON_AddNumberToObject(a,"frame",30);
        cJSON_AddStringToObject(a,"fps","25");
        sds r=tools_run("timecode",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"frame2sec parses");
        if(p){
            double s=cJSON_GetNumberValue(cJSON_GetObjectItem(p,"seconds"));
            CHECK(close_enough(s,1.2),"1.2 seconds");
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"seconds_rational")),"6/5")==0,"rational 6/5");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 4. rescale between rational timebases */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","rescale");
        cJSON_AddNumberToObject(a,"value",44100);
        cJSON_AddStringToObject(a,"from","1/44100");
        cJSON_AddStringToObject(a,"to","1/1000");
        sds r=tools_run("timecode",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"rescale parses");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"result")),1000,"rescaled to 1000");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 5. sec2frame 1.5s @ 30fps = 45 */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","sec2frame");
        cJSON_AddStringToObject(a,"seconds","1.5");
        cJSON_AddStringToObject(a,"fps","30");
        sds r=tools_run("timecode",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"sec2frame parses");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"frame")),45,"45 frames");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 6. non-drop timecode uses colon frame separator */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","tc_format");
        cJSON_AddNumberToObject(a,"frames",4146);
        cJSON_AddStringToObject(a,"fps","29.97");
        sds r=tools_run("timecode",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"tc_format non-drop parses");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"timecode")),"00:02:18:06")==0,"colon separator");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 7. malformed timecode -> error */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","tc_parse");
        cJSON_AddStringToObject(a,"timecode","not a code");
        sds r=tools_run("timecode",a,NULL);
        CHECK(IS_ERR(r),"bad timecode errors");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 8. missing fps for frame2sec -> error */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","frame2sec");
        cJSON_AddNumberToObject(a,"frame",30);
        sds r=tools_run("timecode",a,NULL);
        CHECK(IS_ERR(r),"missing fps errors");
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("timecode");
}
