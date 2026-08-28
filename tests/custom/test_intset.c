#include "alpha.h"
#include "test_util.h"
extern sds tools_run(const char *name, cJSON *args, const char *cwd);

/* helpers */
static cJSON *intset_add_args(int64_t *vals, int n) {
    cJSON *a=cJSON_CreateObject();
    cJSON_AddStringToObject(a,"op","add");
    cJSON *arr=cJSON_CreateArray();
    for(int i=0;i<n;i++) cJSON_AddItemToArray(arr,cJSON_CreateNumber((double)vals[i]));
    cJSON_AddItemToObject(a,"values",arr);
    return a;
}
static void check_add_sorted(const char *label, int64_t *in, int nin, int64_t *exp, int nexp, const char *enc) {
    TEST_BEGIN(label);
    cJSON *args=intset_add_args(in,nin);
    sds res=tools_run("intset",args,".");
    cJSON_Delete(args);
    CHECK(res!=NULL,"response");
    cJSON *r=cJSON_Parse(res); sdsfree(res);
    CHECK(r!=NULL,"valid json");
    if(!r) return;
    cJSON *encj=cJSON_GetObjectItem(r,"encoding");
    CHECK(encj && encj->valuestring && strcmp(encj->valuestring,enc)==0,"encoding");
    cJSON *len=cJSON_GetObjectItem(r,"len");
    CHECK(len && (int)len->valuedouble==nexp,"len");
    cJSON *vals=cJSON_GetObjectItem(r,"values");
    CHECK(vals && cJSON_GetArraySize(vals)==nexp,"values count");
    if(vals){
        for(int i=0;i<nexp;i++){
            cJSON *el=cJSON_GetArrayItem(vals,i);
            CHECK(el && (int64_t)el->valuedouble==exp[i],"value order");
        }
    }
    cJSON_Delete(r);
}

static void test_basic_sorted(void){
    int64_t in[]={3,1,2};
    int64_t exp[]={1,2,3};
    check_add_sorted("intset: basic sorted insert int16",in,3,exp,3,"int16");
}
static void test_dedup(void){
    TEST_BEGIN("intset: duplicate suppression");
    int64_t in[]={5,5,1,5};
    cJSON *args=intset_add_args(in,4);
    sds res=tools_run("intset",args,"."); cJSON_Delete(args);
    CHECK(res!=NULL,"resp");
    cJSON *r=cJSON_Parse(res); sdsfree(res);
    CHECK(r!=NULL,"json");
    cJSON *len=cJSON_GetObjectItem(r,"len");
    CHECK(len && (int)len->valuedouble==2,"dedup len 2");
    cJSON *added=cJSON_GetObjectItem(r,"added");
    CHECK(added && (int)added->valuedouble==2,"added count 2");
    cJSON_Delete(r);
}
static void test_upgrade_int32(void){
    int64_t in[]={-100, 32767, 32768};
    int64_t exp[]={-100,32767,32768};
    check_add_sorted("intset: upgrade int16->int32 at 32768",in,3,exp,3,"int32");
}
static void test_upgrade_int64(void){
    int64_t in[]={0, 2147483647, 2147483648LL};
    int64_t exp[]={0,2147483647,2147483648LL};
    check_add_sorted("intset: upgrade to int64 at 2^31",in,3,exp,3,"int64");
}
static void test_negative_prepend(void){
    int64_t in[]={100, -50000};
    int64_t exp[]={-50000,100};
    check_add_sorted("intset: negative value prepend with upgrade",in,2,exp,2,"int32");
}
static void test_remove(void){
    TEST_BEGIN("intset: remove existing and missing");
    int64_t in[]={1,2,3,4,5};
    cJSON *args=cJSON_CreateObject();
    cJSON_AddStringToObject(args,"op","remove");
    cJSON *arr=cJSON_CreateArray(); for(int i=0;i<5;i++) cJSON_AddItemToArray(arr,cJSON_CreateNumber((double)in[i]));
    cJSON_AddItemToObject(args,"values",arr);
    cJSON *targ=cJSON_CreateArray(); cJSON_AddItemToArray(targ,cJSON_CreateNumber(3)); cJSON_AddItemToArray(targ,cJSON_CreateNumber(99));
    cJSON_AddItemToObject(args,"targets",targ);
    sds res=tools_run("intset",args,"."); cJSON_Delete(args);
    CHECK(res!=NULL,"resp");
    cJSON *r=cJSON_Parse(res); sdsfree(res);
    CHECK(r!=NULL,"json");
    cJSON *len=cJSON_GetObjectItem(r,"len");
    CHECK(len && (int)len->valuedouble==4,"len after remove 1");
    cJSON *removed=cJSON_GetObjectItem(r,"removed");
    CHECK(removed && cJSON_GetArraySize(removed)==2,"removed array size");
    if(removed){
        CHECK(cJSON_IsTrue(cJSON_GetArrayItem(removed,0)),"removed existing true");
        CHECK(cJSON_IsFalse(cJSON_GetArrayItem(removed,1)),"removed missing false");
    }
    cJSON_Delete(r);
}
static void test_find(void){
    TEST_BEGIN("intset: find binary search");
    int64_t in[]={10,20,30};
    cJSON *args=cJSON_CreateObject();
    cJSON_AddStringToObject(args,"op","find");
    cJSON *arr=cJSON_CreateArray(); for(int i=0;i<3;i++) cJSON_AddItemToArray(arr,cJSON_CreateNumber((double)in[i]));
    cJSON_AddItemToObject(args,"values",arr);
    cJSON_AddNumberToObject(args,"target",20);
    sds res=tools_run("intset",args,"."); cJSON_Delete(args);
    CHECK(res!=NULL,"resp");
    cJSON *r=cJSON_Parse(res); sdsfree(res);
    CHECK(r!=NULL,"json");
    cJSON *found=cJSON_GetObjectItem(r,"found");
    CHECK(found && cJSON_IsTrue(found),"found true");
    cJSON *idx=cJSON_GetObjectItem(r,"index");
    CHECK(idx && (int)idx->valuedouble==1,"index 1");
    cJSON_Delete(r);
    /* not found */
    cJSON *args2=cJSON_CreateObject();
    cJSON_AddStringToObject(args2,"op","find");
    cJSON *arr2=cJSON_CreateArray(); for(int i=0;i<3;i++) cJSON_AddItemToArray(arr2,cJSON_CreateNumber((double)in[i]));
    cJSON_AddItemToObject(args2,"values",arr2);
    cJSON_AddNumberToObject(args2,"target",99);
    sds res2=tools_run("intset",args2,"."); cJSON_Delete(args2);
    cJSON *r2=cJSON_Parse(res2); sdsfree(res2);
    CHECK(r2!=NULL,"json2");
    cJSON *found2=cJSON_GetObjectItem(r2,"found");
    CHECK(found2 && cJSON_IsFalse(found2),"found false");
    cJSON *idx2=cJSON_GetObjectItem(r2,"index");
    CHECK(idx2 && (int)idx2->valuedouble==-1,"index -1");
    cJSON_Delete(r2);
}
static void test_get(void){
    TEST_BEGIN("intset: get by index");
    int64_t in[]={5,10,15};
    cJSON *args=cJSON_CreateObject();
    cJSON_AddStringToObject(args,"op","get");
    cJSON *arr=cJSON_CreateArray(); for(int i=0;i<3;i++) cJSON_AddItemToArray(arr,cJSON_CreateNumber((double)in[i]));
    cJSON_AddItemToObject(args,"values",arr);
    cJSON_AddNumberToObject(args,"index",1);
    sds res=tools_run("intset",args,"."); cJSON_Delete(args);
    CHECK(res!=NULL,"resp");
    cJSON *r=cJSON_Parse(res); sdsfree(res);
    CHECK(r!=NULL,"json");
    cJSON *val=cJSON_GetObjectItem(r,"value");
    CHECK(val && (int)val->valuedouble==10,"value at 1 is 10");
    cJSON_Delete(r);
}
static void test_adversarial(void){
    TEST_BEGIN("intset: adversarial negative/out-of-bounds/corrupted");
    /* negative index */
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"op","get");
        cJSON *arr=cJSON_CreateArray(); cJSON_AddItemToArray(arr,cJSON_CreateNumber(1)); cJSON_AddItemToArray(arr,cJSON_CreateNumber(2));
        cJSON_AddItemToObject(args,"values",arr);
        cJSON_AddNumberToObject(args,"index",-1);
        sds res=tools_run("intset",args,"."); cJSON_Delete(args);
        CHECK(res!=NULL,"neg index resp");
        CHECK(strstr(res,"ERROR:")!=NULL,"negative index rejected");
        sdsfree(res);
    }
    /* out of bounds */
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"op","get");
        cJSON *arr=cJSON_CreateArray(); cJSON_AddItemToArray(arr,cJSON_CreateNumber(1));
        cJSON_AddItemToObject(args,"values",arr);
        cJSON_AddNumberToObject(args,"index",5);
        sds res=tools_run("intset",args,"."); cJSON_Delete(args);
        CHECK(strstr(res,"ERROR:")!=NULL,"oob index rejected");
        sdsfree(res);
    }
    /* non-integer float */
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"op","add");
        cJSON *arr=cJSON_CreateArray(); cJSON_AddItemToArray(arr,cJSON_CreateNumber(1.5));
        cJSON_AddItemToObject(args,"values",arr);
        sds res=tools_run("intset",args,"."); cJSON_Delete(args);
        CHECK(strstr(res,"ERROR:")!=NULL,"float 1.5 rejected");
        sdsfree(res);
    }
    /* corrupted string in values */
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"op","add");
        cJSON *arr=cJSON_CreateArray(); cJSON_AddItemToArray(arr,cJSON_CreateString("corrupted"));
        cJSON_AddItemToObject(args,"values",arr);
        sds res=tools_run("intset",args,"."); cJSON_Delete(args);
        CHECK(strstr(res,"ERROR:")!=NULL,"string value rejected");
        sdsfree(res);
    }
    /* values not array */
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"op","add");
        cJSON_AddStringToObject(args,"values","notarray");
        sds res=tools_run("intset",args,"."); cJSON_Delete(args);
        CHECK(strstr(res,"ERROR:")!=NULL,"non-array values rejected");
        sdsfree(res);
    }
    /* empty set random */
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"op","random");
        cJSON *arr=cJSON_CreateArray();
        cJSON_AddItemToObject(args,"values",arr);
        sds res=tools_run("intset",args,"."); cJSON_Delete(args);
        CHECK(strstr(res,"ERROR:")!=NULL,"random empty rejected");
        sdsfree(res);
    }
    /* NULL args fuzz */
    {
        sds res=tools_run("intset",NULL,".");
        CHECK(res!=NULL,"null args resp");
        /* should not crash; may return empty set or error */
        sdsfree(res);
    }
    /* unknown op */
    {
        cJSON *args=cJSON_CreateObject();
        cJSON_AddStringToObject(args,"op","bogus_op");
        sds res=tools_run("intset",args,"."); cJSON_Delete(args);
        CHECK(strstr(res,"ERROR:")!=NULL,"unknown op rejected");
        sdsfree(res);
    }
}

int main(void){
    test_basic_sorted();
    test_dedup();
    test_upgrade_int32();
    test_upgrade_int64();
    test_negative_prepend();
    test_remove();
    test_find();
    test_get();
    test_adversarial();
    return test_report("test_intset");
}
