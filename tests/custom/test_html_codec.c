#include "alpha.h"
#include "test_util.h"
static cJSON *P(sds s){ return cJSON_Parse(s); }
int main(void){
    TEST_BEGIN("html_codec");
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","decode");
        cJSON_AddStringToObject(a,"text","Tom &amp; Jerry &lt;friends&gt; &quot;always&quot; &apos;forever&apos; &copy; 2026 &euro; 100");
        sds r=tools_run("html_codec",a,NULL);
        CHECK(r!=NULL,"html_codec returns response");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json returned");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"ok")==0,"status ok");
            CHECK(strstr(cJSON_GetStringValue(cJSON_GetObjectItem(p,"result")),"Tom & Jerry <friends> \"always\" 'forever'")!=NULL,"decoded correctly");
            CHECK(cJSON_GetObjectItem(p,"entities_decoded")->valueint==9,"decoded 9 entities");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","decode");
        cJSON_AddStringToObject(a,"text","Hex: &#x3C;&#x3E;&#x26;&#x20AC; Decimal: &#60;&#62;&#38;&#8364; Apostrophe: &#39;");
        sds r=tools_run("html_codec",a,NULL);
        CHECK(r!=NULL,"response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json returned");
        if(p){
            CHECK(strstr(cJSON_GetStringValue(cJSON_GetObjectItem(p,"result")),"Hex: <>&")!=NULL,"hex and dec numeric entities decoded");
            CHECK(cJSON_GetObjectItem(p,"entities_decoded")->valueint==9,"decoded 9 entities");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","encode");
        cJSON_AddStringToObject(a,"text","<div class=\"hero\">Tom & Jerry's</div>");
        sds r=tools_run("html_codec",a,NULL);
        CHECK(r!=NULL,"response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"result")),"&lt;div class=&quot;hero&quot;&gt;Tom &amp; Jerry&#39;s&lt;/div&gt;")==0,"encoded matches");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","strip_tags");
        cJSON_AddStringToObject(a,"text","<p>Hello <b>World</b> &amp; universe!<script>alert(1);</script><style>body{}</style></p>");
        sds r=tools_run("html_codec",a,NULL);
        CHECK(r!=NULL,"response returned");
        cJSON *p=P(r);
        CHECK(p!=NULL,"valid json");
        if(p){
            CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"result")),"Hello World & universe!")==0,"tags stripped and scripts ignored");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","decode");
        sds r=tools_run("html_codec",a,NULL);
        CHECK(r!=NULL,"missing text handled");
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"error")==0,"error returned"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","nonexistent");
        cJSON_AddStringToObject(a,"text","test");
        sds r=tools_run("html_codec",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"status")),"error")==0,"unknown action rejected"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","decode");
        cJSON_AddStringToObject(a,"text","A & B &amp &invalid; &");
        sds r=tools_run("html_codec",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(p,"result")),"A & B &amp &invalid; &")==0,"stray ampersand preserved"); cJSON_Delete(p); }
        sdsfree(r); cJSON_Delete(a);
    }
    return test_report("html_codec");
}
