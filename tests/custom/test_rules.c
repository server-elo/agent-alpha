/* test_rules.c — tests for rules (Tasmota-style rules evaluator) tool */
#include "alpha.h"
#include "test_util.h"

extern sds tools_run(const char *name, cJSON *args, const char *cwd);
static cJSON *P(sds s){ if(!s) return NULL; return cJSON_Parse(s); }
static int IS_ERR(sds r){ return r && strncmp(r,"ERROR",5)==0; }

static cJSON *ev(const char *json){ return cJSON_Parse(json); }

int main(void){
    TEST_BEGIN("rules");

    /* 1. eval: numeric comparison fires */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"rules","ON DHT11#Temperature>25 DO Power1 1");
        cJSON_AddItemToObject(a,"event",ev("{\"DHT11\":{\"Temperature\":26}}"));
        sds r=tools_run("rules",a,NULL);
        cJSON *p=P(r);
        CHECK(p!=NULL,"eval fires JSON");
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"fired")),1,"one command fired");
            cJSON *c=cJSON_GetObjectItem(p,"commands");
            CHECK(c && cJSON_GetArraySize(c)==1 && strcmp(cJSON_GetArrayItem(c,0)->valuestring,"Power1 1")==0,"command is 'Power1 1'");
            cJSON_Delete(p);
        }
        sdsfree(r); cJSON_Delete(a);
    }
    /* 2. eval: comparison below threshold does not fire */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"rules","ON DHT11#Temperature>25 DO Power1 1");
        cJSON_AddItemToObject(a,"event",ev("{\"DHT11\":{\"Temperature\":20}}"));
        sds r=tools_run("rules",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"fired")),0,"20>25 no fire"); cJSON_Delete(p); }
        else CHECK(0,"no-fire parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 3. eval: boundary — > vs >= at exactly 25 */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"rules","ON t>25 DO gt\nON t>=25 DO ge");
        cJSON_AddItemToObject(a,"event",ev("{\"t\":25}"));
        sds r=tools_run("rules",a,NULL);
        cJSON *p=P(r);
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"fired")),1,"only >= fires at boundary");
            cJSON *c=cJSON_GetObjectItem(p,"commands");
            CHECK(c && cJSON_GetArraySize(c)==1 && strcmp(cJSON_GetArrayItem(c,0)->valuestring,"ge")==0,"boundary command is ge");
            cJSON_Delete(p);
        } else CHECK(0,"boundary parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 4. eval: equality, presence, ENDON, multiple commands */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"rules","ON Power1#State==1 DO Power2 0 ENDON\nON System#Boot DO Power1 1; Delay 10; Power2 1 ENDON");
        cJSON_AddItemToObject(a,"event",ev("{\"Power1\":{\"State\":1},\"System\":{\"Boot\":1}}"));
        sds r=tools_run("rules",a,NULL);
        cJSON *p=P(r);
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"fired")),4,"4 commands from 2 rules");
            cJSON *c=cJSON_GetObjectItem(p,"commands");
            if(c && cJSON_GetArraySize(c)==4){
                CHECK(strcmp(cJSON_GetArrayItem(c,0)->valuestring,"Power2 0")==0,"rule1 cmd");
                CHECK(strcmp(cJSON_GetArrayItem(c,1)->valuestring,"Power1 1")==0,"presence cmd1");
                CHECK(strcmp(cJSON_GetArrayItem(c,3)->valuestring,"Power2 1")==0,"presence cmd3");
            } else CHECK(0,"4-command array");
            cJSON_Delete(p);
        } else CHECK(0,"multi-rule parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 5. eval: case-insensitive keywords and event keys */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"rules","on DHT11#TEMPERATURE>=18.5 do Power1 1 endon");
        cJSON_AddItemToObject(a,"event",ev("{\"dht11\":{\"temperature\":18.5}}"));
        sds r=tools_run("rules",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"fired")),1,"case-insensitive + float boundary fires"); cJSON_Delete(p); }
        else CHECK(0,"case-insensitive parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 6. eval: flat {name,value} event shape */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"rules","ON temperature>25 DO Power1 1");
        cJSON_AddItemToObject(a,"event",ev("{\"name\":\"Temperature\",\"value\":26}"));
        sds r=tools_run("rules",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"fired")),1,"flat name/value shape fires"); cJSON_Delete(p); }
        else CHECK(0,"flat shape parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 7. eval: string equality and inequality */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"rules","ON Mode==auto DO Power1 1\nON Mode!=auto DO Power1 0");
        cJSON_AddItemToObject(a,"event",ev("{\"Mode\":\"auto\"}"));
        sds r=tools_run("rules",a,NULL);
        cJSON *p=P(r);
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"fired")),1,"string == fires, != does not");
            cJSON *c=cJSON_GetObjectItem(p,"commands");
            CHECK(c && strcmp(cJSON_GetArrayItem(c,0)->valuestring,"Power1 1")==0,"string-eq command");
            cJSON_Delete(p);
        } else CHECK(0,"string eq parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 8. eval: negative-number comparison and '=' alias */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"rules","ON temperature<-5 DO Heater 1\nON state=3 DO Led 1");
        cJSON_AddItemToObject(a,"event",ev("{\"temperature\":-10,\"state\":3}"));
        sds r=tools_run("rules",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"fired")),2,"negative cmp and '=' alias fire"); cJSON_Delete(p); }
        else CHECK(0,"negative cmp parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 9. eval: absent event key never fires */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"rules","ON Zigbee#Illuminance>100 DO Power1 1");
        cJSON_AddItemToObject(a,"event",ev("{\"DHT11\":{\"Temperature\":26}}"));
        sds r=tools_run("rules",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"fired")),0,"absent key no fire"); cJSON_Delete(p); }
        else CHECK(0,"absent key parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 10. eval: non-numeric event value against numeric trigger does not fire */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"rules","ON temperature>25 DO Power1 1");
        cJSON_AddItemToObject(a,"event",ev("{\"temperature\":\"hot\"}"));
        sds r=tools_run("rules",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"fired")),0,"non-numeric event value no fire"); cJSON_Delete(p); }
        else CHECK(0,"non-numeric event parse");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 11. parse: structure of a two-rule set */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"rules","ON DHT11#Temperature>25 DO Power1 1; Buzzer 2\n\nON Switch1#State DO Power1 TOGGLE");
        sds r=tools_run("rules",a,NULL);
        cJSON *p=P(r);
        if(p){
            CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"rules")),2,"parse counts 2 rules (blank skipped)");
            cJSON *items=cJSON_GetObjectItem(p,"items");
            cJSON *r1=cJSON_GetArrayItem(items,0);
            CHECK(r1 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(r1,"trigger")),"DHT11#Temperature")==0,"rule1 trigger");
            CHECK(r1 && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(r1,"op")),">")==0,"rule1 op");
            CHECK(r1 && cJSON_GetNumberValue(cJSON_GetObjectItem(r1,"value"))==25.0,"rule1 value 25");
            cJSON *r2=cJSON_GetArrayItem(items,1);
            CHECK(r2 && cJSON_IsNull(cJSON_GetObjectItem(r2,"op")),"rule2 presence op null");
            CHECK(r2 && (int)cJSON_GetNumberValue(cJSON_GetObjectItem(r2,"line"))==3,"rule2 line 3");
            cJSON_Delete(p);
        } else CHECK(0,"parse structure");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 12. negative: missing DO */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"rules","ON temperature>25 Power1 1");
        cJSON_AddItemToObject(a,"event",ev("{}"));
        sds r=tools_run("rules",a,NULL);
        CHECK(IS_ERR(r),"missing DO is error");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 13. negative: relational operator with non-numeric value */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"rules","ON temperature>abc DO Power1 1");
        sds r=tools_run("rules",a,NULL);
        CHECK(IS_ERR(r),"relational op on non-numeric is error");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 14. negative: overflow-sized number in trigger */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"rules","ON t>1e999 DO Power1 1");
        sds r=tools_run("rules",a,NULL);
        CHECK(IS_ERR(r),"1e999 overflow is error");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 15. negative: empty rules text */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"rules","   \n  \n");
        cJSON_AddItemToObject(a,"event",ev("{}"));
        sds r=tools_run("rules",a,NULL);
        CHECK(IS_ERR(r),"blank-only rules is error");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 16. negative: missing rules param */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddItemToObject(a,"event",ev("{}"));
        sds r=tools_run("rules",a,NULL);
        CHECK(IS_ERR(r),"missing rules param is error");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 17. negative: missing event for eval */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"rules","ON t>1 DO x");
        sds r=tools_run("rules",a,NULL);
        CHECK(IS_ERR(r),"missing event is error");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 18. negative: empty trigger name */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"rules","ON >25 DO Power1 1");
        sds r=tools_run("rules",a,NULL);
        CHECK(IS_ERR(r),"empty trigger name is error");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 19. negative: no commands after DO */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"rules","ON t>1 DO ENDON");
        sds r=tools_run("rules",a,NULL);
        CHECK(IS_ERR(r),"empty command list is error");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 20. negative: stray ';' (empty command) */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"rules","ON t>1 DO Power1 1;;Power2 0");
        sds r=tools_run("rules",a,NULL);
        CHECK(IS_ERR(r),"stray semicolon is error");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 21. negative: rule not starting with ON */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","parse");
        cJSON_AddStringToObject(a,"rules","WHEN t>1 DO x");
        sds r=tools_run("rules",a,NULL);
        CHECK(IS_ERR(r),"rule must start with ON");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 22. negative: unknown action */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","explode");
        cJSON_AddStringToObject(a,"rules","ON t>1 DO x");
        sds r=tools_run("rules",a,NULL);
        CHECK(IS_ERR(r),"unknown action is error");
        sdsfree(r); cJSON_Delete(a);
    }
    /* 23. eval: event passed as JSON-encoded string is accepted */
    {
        cJSON *a=cJSON_CreateObject();
        cJSON_AddStringToObject(a,"action","eval");
        cJSON_AddStringToObject(a,"rules","ON t>1 DO x");
        cJSON_AddStringToObject(a,"event","{\"t\":2}");
        sds r=tools_run("rules",a,NULL);
        cJSON *p=P(r);
        if(p){ CHECK_EQ_INT((int)cJSON_GetNumberValue(cJSON_GetObjectItem(p,"fired")),1,"event as JSON string fires"); cJSON_Delete(p); }
        else CHECK(0,"event-string parse");
        sdsfree(r); cJSON_Delete(a);
    }

    return test_report("rules");
}
