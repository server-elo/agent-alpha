#include "alpha.h"
#include "test_util.h"
sds tools_run(const char *name, cJSON *args, const char *cwd);
int main(void){
 TEST_BEGIN("mqtt_topic");
 // 1 exact match
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","match"); cJSON_AddStringToObject(a,"topic","tasmota/tele/STATE"); cJSON_AddStringToObject(a,"filter","tasmota/tele/STATE"); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"\"match\":true")!=NULL,"exact match true"); sdsfree(r); cJSON_Delete(a); }
 // 2 + wildcard single level
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","match"); cJSON_AddStringToObject(a,"topic","tasmota/tele/STATE"); cJSON_AddStringToObject(a,"filter","tasmota/+/STATE"); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"\"match\":true")!=NULL,"+ wildcard matches"); sdsfree(r); cJSON_Delete(a); }
 // 3 # wildcard multi-level
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","match"); cJSON_AddStringToObject(a,"topic","tasmota/tele/SENSOR"); cJSON_AddStringToObject(a,"filter","tasmota/#"); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"\"match\":true")!=NULL,"# matches remainder"); sdsfree(r); cJSON_Delete(a); }
 // 4 # alone matches any
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","match"); cJSON_AddStringToObject(a,"topic","a/b/c"); cJSON_AddStringToObject(a,"filter","#"); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"\"match\":true")!=NULL,"# alone matches"); sdsfree(r); cJSON_Delete(a); }
 // 5 no match
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","match"); cJSON_AddStringToObject(a,"topic","tasmota/stat/POWER"); cJSON_AddStringToObject(a,"filter","tasmota/tele/+"); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"\"match\":false")!=NULL,"non-match false"); sdsfree(r); cJSON_Delete(a); }
 // 6 validate_topic valid
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","validate_topic"); cJSON_AddStringToObject(a,"topic","tasmota/tele/STATE"); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"\"valid\":true")!=NULL,"validate_topic valid"); sdsfree(r); cJSON_Delete(a); }
 // 7 validate_topic rejects wildcard
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","validate_topic"); cJSON_AddStringToObject(a,"topic","a/+/c"); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"\"valid\":false")!=NULL,"topic with + invalid"); sdsfree(r); cJSON_Delete(a); }
 // 8 validate_filter valid with +/#
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","validate_filter"); cJSON_AddStringToObject(a,"filter","tasmota/+/STATE"); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"\"valid\":true")!=NULL,"filter with + valid"); sdsfree(r); cJSON_Delete(a); }
 // 9 validate_filter rejects malformed: '#' not last
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","validate_filter"); cJSON_AddStringToObject(a,"filter","a/#/c"); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"\"valid\":false")!=NULL,"filter # not last invalid"); sdsfree(r); cJSON_Delete(a); }
 // 10 validate_filter rejects embedded wildcard
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","validate_filter"); cJSON_AddStringToObject(a,"filter","ab+"); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"\"valid\":false")!=NULL,"embedded + invalid"); sdsfree(r); cJSON_Delete(a); }
 // 11 route multi-filter
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","route"); cJSON_AddStringToObject(a,"topic","tasmota/tele/SENSOR"); cJSON *arr=cJSON_CreateArray(); cJSON_AddItemToArray(arr,cJSON_CreateString("tasmota/#")); cJSON_AddItemToArray(arr,cJSON_CreateString("tasmota/+/SENSOR")); cJSON_AddItemToArray(arr,cJSON_CreateString("stat/#")); cJSON_AddItemToObject(a,"filters",arr); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"tasmota/#")!=NULL,"route includes tasmota/#"); CHECK(strstr(r,"tasmota/+/SENSOR")!=NULL,"route includes +/SENSOR"); CHECK(strstr(r,"\"count\":2")!=NULL,"route count 2"); CHECK(strstr(r,"stat/#")==NULL,"route excludes non-matching"); sdsfree(r); cJSON_Delete(a); }
 // 12 extract wildcards
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","extract"); cJSON_AddStringToObject(a,"topic","tasmota/tele/STATE"); cJSON_AddStringToObject(a,"filter","tasmota/+/+"); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"\"match\":true")!=NULL,"extract match true"); CHECK(strstr(r,"tele")!=NULL,"extract plus tele"); CHECK(strstr(r,"STATE")!=NULL,"extract plus STATE"); sdsfree(r); cJSON_Delete(a); }
 // 13 extract hash remainder
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","extract"); cJSON_AddStringToObject(a,"topic","a/b/c/d"); cJSON_AddStringToObject(a,"filter","a/#"); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"b/c/d")!=NULL,"extract hash b/c/d"); sdsfree(r); cJSON_Delete(a); }
 // 14 adversarial: negative max_levels
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","match"); cJSON_AddStringToObject(a,"topic","a/b"); cJSON_AddStringToObject(a,"filter","a/b"); cJSON_AddNumberToObject(a,"max_levels",-5); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"ERROR")!=NULL && strstr(r,"non-negative")!=NULL,"negative max_levels rejected"); sdsfree(r); cJSON_Delete(a); }
 // 15 adversarial: invalid charset control char
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","validate_topic"); cJSON_AddStringToObject(a,"topic","a/\x01/c"); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"\"valid\":false")!=NULL,"control char invalid"); sdsfree(r); cJSON_Delete(a); }
 // 16 adversarial: empty topic
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","validate_topic"); cJSON_AddStringToObject(a,"topic",""); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"\"valid\":false")!=NULL || strstr(r,"ERROR")!=NULL,"empty topic invalid"); sdsfree(r); cJSON_Delete(a); }
 // 17 adversarial: corrupted filter out-of-bounds like "a/#/c" already tested but also test topic with wildcards in match should error
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","match"); cJSON_AddStringToObject(a,"topic","a/#/c"); cJSON_AddStringToObject(a,"filter","a/b/c"); sds r=tools_run("mqtt_topic",a,NULL); CHECK(strstr(r,"invalid topic")!=NULL,"topic with # rejected in match"); sdsfree(r); cJSON_Delete(a); }
 // 18 alias mqtt
 { cJSON *a=cJSON_CreateObject(); cJSON_AddStringToObject(a,"action","match"); cJSON_AddStringToObject(a,"topic","x/y"); cJSON_AddStringToObject(a,"filter","x/+"); sds r=tools_run("mqtt",a,NULL); CHECK(strstr(r,"\"match\":true")!=NULL,"alias mqtt works"); sdsfree(r); cJSON_Delete(a); }

 return test_report("mqtt_topic");
}
