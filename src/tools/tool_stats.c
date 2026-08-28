/* tool_stats.c — Pure-C statistical analysis suite
 * Actions: describe, histogram, correlation, normalize, percentile
 * No I/O, no external deps beyond cJSON/sds/math.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <float.h>

#define STATS_MAX_N 100000
#define STATS_MAX_BINS 256

static int stats_cmp_dbl(const void *a, const void *b) {
    double da = *(const double*)a;
    double db = *(const double*)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

/* Extract double array from args field `key`.
 * Supports: JSON array directly, or JSON string encoding an array, or comma-separated numbers.
 * Returns count via out_n, array malloc'd (caller free), NULL on error.
 * On error, *err_msg is set to sds error (caller frees), otherwise NULL.
 */
static double *stats_get_array(cJSON *args, const char *key, size_t *out_n, sds *err_msg) {
    *out_n = 0;
    *err_msg = NULL;
    cJSON *item = cJSON_GetObjectItem(args, key);
    if (!item) return NULL;
    cJSON *arr = NULL;
    double *buf = NULL;
    size_t n = 0;
    if (cJSON_IsArray(item)) {
        arr = item;
    } else if (cJSON_IsString(item) && item->valuestring) {
        const char *s = item->valuestring;
        /* trim leading space */
        while (*s && isspace((unsigned char)*s)) s++;
        if (*s == '[') {
            cJSON *parsed = cJSON_Parse(item->valuestring);
            if (!parsed || !cJSON_IsArray(parsed)) {
                if (parsed) cJSON_Delete(parsed);
                *err_msg = sdscatprintf(sdsempty(), "ERROR: field '%s' string is not a JSON array", key);
                return NULL;
            }
            arr = parsed;
            n = (size_t)cJSON_GetArraySize(arr);
            if (n == 0) { cJSON_Delete(arr); *err_msg = sdscatprintf(sdsempty(), "ERROR: field '%s' array is empty", key); return NULL; }
            if (n > STATS_MAX_N) { cJSON_Delete(arr); *err_msg = sdscatprintf(sdsempty(), "ERROR: field '%s' exceeds max %d elements", key, STATS_MAX_N); return NULL; }
            buf = (double*)malloc(n * sizeof(double));
            if (!buf) { cJSON_Delete(arr); *err_msg = sdsnew("ERROR: allocation failed"); return NULL; }
            for (size_t i=0;i<n;i++) {
                cJSON *e = cJSON_GetArrayItem(arr,(int)i);
                if (!cJSON_IsNumber(e)) { free(buf); cJSON_Delete(arr); *err_msg = sdscatprintf(sdsempty(), "ERROR: field '%s' contains non-number at index %zu", key, i); return NULL; }
                buf[i]=e->valuedouble;
            }
            cJSON_Delete(arr);
            *out_n=n;
            return buf;
        } else if (*s==0) {
            *err_msg = sdscatprintf(sdsempty(), "ERROR: field '%s' is empty string", key);
            return NULL;
        } else {
            /* try comma-separated */
            /* count commas */
            size_t cnt=1;
            for (const char *p=s;*p;p++) if(*p==',') cnt++;
            if (cnt>STATS_MAX_N) { *err_msg = sdscatprintf(sdsempty(), "ERROR: field '%s' exceeds max %d", key, STATS_MAX_N); return NULL; }
            buf=(double*)malloc(cnt*sizeof(double));
            if(!buf){ *err_msg=sdsnew("ERROR: allocation failed"); return NULL; }
            char *copy=strdup(s);
            if(!copy){ free(buf); *err_msg=sdsnew("ERROR: allocation failed"); return NULL; }
            size_t idx=0;
            char *tok=strtok(copy,",");
            while(tok && idx<cnt){
                while(*tok && isspace((unsigned char)*tok)) tok++;
                char *end=tok+strlen(tok)-1;
                while(end>tok && isspace((unsigned char)*end)){*end=0;end--;}
                if(*tok==0){ free(buf); free(copy); *err_msg=sdscatprintf(sdsempty(),"ERROR: field '%s' has empty element",key); return NULL; }
                char *ep=NULL;
                double v=strtod(tok,&ep);
                if(!ep||*ep!=0){ free(buf); free(copy); *err_msg=sdscatprintf(sdsempty(),"ERROR: field '%s' invalid number '%s'",key,tok); return NULL; }
                buf[idx++]=v;
                tok=strtok(NULL,",");
            }
            free(copy);
            if(idx==0){ free(buf); *err_msg=sdscatprintf(sdsempty(),"ERROR: field '%s' empty",key); return NULL; }
            *out_n=idx;
            return buf;
        }
    } else if (cJSON_IsNumber(item)) {
        buf=(double*)malloc(sizeof(double));
        if(!buf){ *err_msg=sdsnew("ERROR: allocation failed"); return NULL; }
        buf[0]=item->valuedouble;
        *out_n=1;
        return buf;
    } else {
        *err_msg=sdscatprintf(sdsempty(),"ERROR: field '%s' must be array or string",key);
        return NULL;
    }
    /* array direct path */
    n=(size_t)cJSON_GetArraySize(arr);
    if(n==0){ *err_msg=sdscatprintf(sdsempty(),"ERROR: field '%s' array is empty",key); return NULL; }
    if(n>STATS_MAX_N){ *err_msg=sdscatprintf(sdsempty(),"ERROR: field '%s' exceeds max %d",key,STATS_MAX_N); return NULL; }
    buf=(double*)malloc(n*sizeof(double));
    if(!buf){ *err_msg=sdsnew("ERROR: allocation failed"); return NULL; }
    for(size_t i=0;i<n;i++){
        cJSON *e=cJSON_GetArrayItem(arr,(int)i);
        if(!cJSON_IsNumber(e)){ free(buf); *err_msg=sdscatprintf(sdsempty(),"ERROR: field '%s' contains non-number at index %zu",key,i); return NULL; }
        buf[i]=e->valuedouble;
    }
    *out_n=n;
    return buf;
}

static sds tool_stats_run(cJSON *args, const char *cwd) {
    (void)cwd;
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(args, "action"));
    if (!action || !action[0]) action = "describe";

    if (strcmp(action,"describe")==0) {
        size_t n=0; sds err=NULL;
        double *data = stats_get_array(args, "data", &n, &err);
        if (!data) {
            /* try alternative key "values" */
            if (err) sdsfree(err);
            data = stats_get_array(args, "values", &n, &err);
            if (!data) {
                if (err) return err;
                return sdsnew("ERROR: 'data' array required for describe");
            }
        }
        if (err) sdsfree(err);
        double sum=0, mn=data[0], mx=data[0];
        for(size_t i=0;i<n;i++){ sum+=data[i]; if(data[i]<mn) mn=data[i]; if(data[i]>mx) mx=data[i]; }
        double mean = sum/(double)n;
        /* variance (population) and stddev */
        double var=0;
        for(size_t i=0;i<n;i++){ double d=data[i]-mean; var+=d*d; }
        var/= (double)n;
        double stdev = sqrt(var);
        /* median */
        double *sorted=(double*)malloc(n*sizeof(double));
        if(!sorted){ free(data); return sdsnew("ERROR: allocation failed"); }
        memcpy(sorted,data,n*sizeof(double));
        qsort(sorted,n,sizeof(double),stats_cmp_dbl);
        double median;
        if(n%2==1) median=sorted[n/2];
        else median=(sorted[n/2-1]+sorted[n/2])/2.0;
        /* minmax range */
        double range = mx - mn;
        sds out=sdscatprintf(sdsempty(),
            "{\"action\":\"describe\",\"count\":%zu,\"sum\":%.6g,\"mean\":%.6g,\"median\":%.6g,\"min\":%.6g,\"max\":%.6g,\"range\":%.6g,\"variance\":%.6g,\"stdev\":%.6g}",
            n,sum,mean,median,mn,mx,range,var,stdev);
        free(sorted); free(data);
        return out;
    }

    if (strcmp(action,"histogram")==0) {
        size_t n=0; sds err=NULL;
        double *data = stats_get_array(args,"data",&n,&err);
        if(!data){
            if(err) sdsfree(err);
            data=stats_get_array(args,"values",&n,&err);
            if(!data){ if(err) return err; return sdsnew("ERROR: 'data' array required for histogram"); }
        }
        if(err) sdsfree(err);
        int bins=10;
        cJSON *bi=cJSON_GetObjectItem(args,"bins");
        if(cJSON_IsNumber(bi)) bins=bi->valueint;
        else {
            cJSON *b2=cJSON_GetObjectItem(args,"bin_count");
            if(cJSON_IsNumber(b2)) bins=b2->valueint;
        }
        if(bins<1) bins=1;
        if(bins>STATS_MAX_BINS) bins=STATS_MAX_BINS;
        double mn=data[0], mx=data[0];
        for(size_t i=0;i<n;i++){ if(data[i]<mn) mn=data[i]; if(data[i]>mx) mx=data[i]; }
        /* allow override min/max */
        cJSON *jmin=cJSON_GetObjectItem(args,"min"); if(cJSON_IsNumber(jmin)) mn=jmin->valuedouble;
        cJSON *jmax=cJSON_GetObjectItem(args,"max"); if(cJSON_IsNumber(jmax)) mx=jmax->valuedouble;
        if(mx<=mn){ mx=mn+1.0; }
        double width=(mx-mn)/(double)bins;
        int *counts=(int*)calloc((size_t)bins,sizeof(int));
        if(!counts){ free(data); return sdsnew("ERROR: allocation failed"); }
        for(size_t i=0;i<n;i++){
            double v=data[i];
            if(v<mn || v>mx) continue;
            int idx=(int)((v-mn)/width);
            if(idx>=bins) idx=bins-1;
            if(idx<0) idx=0;
            counts[idx]++;
        }
        sds out=sdscatprintf(sdsempty(),"{\"action\":\"histogram\",\"count\":%zu,\"bins\":%d,\"min\":%.6g,\"max\":%.6g,\"width\":%.6g,\"counts\":[",n,bins,mn,mx,width);
        for(int i=0;i<bins;i++){
            if(i) out=sdscat(out,",");
            out=sdscatprintf(out,"%d",counts[i]);
        }
        out=sdscat(out,"],\"edges\":[");
        for(int i=0;i<=bins;i++){
            if(i) out=sdscat(out,",");
            out=sdscatprintf(out,"%.6g",mn+width*i);
        }
        out=sdscat(out,"]}");
        free(counts); free(data);
        return out;
    }

    if (strcmp(action,"correlation")==0) {
        size_t nx=0, ny=0; sds ex=NULL, ey=NULL;
        double *x = stats_get_array(args,"x",&nx,&ex);
        if(!x){
            if(ex) sdsfree(ex);
            x=stats_get_array(args,"data_x",&nx,&ex);
            if(!x){ if(ex) return ex; return sdsnew("ERROR: 'x' array required for correlation"); }
        }
        if(ex) sdsfree(ex);
        double *y = stats_get_array(args,"y",&ny,&ey);
        if(!y){
            if(ey) sdsfree(ey);
            y=stats_get_array(args,"data_y",&ny,&ey);
            if(!y){ free(x); if(ey) return ey; return sdsnew("ERROR: 'y' array required for correlation"); }
        }
        if(ey) sdsfree(ey);
        if(nx!=ny){ free(x); free(y); return sdscatprintf(sdsempty(),"ERROR: correlation requires equal length (x=%zu y=%zu)",nx,ny); }
        if(nx<2){ free(x); free(y); return sdsnew("ERROR: correlation requires at least 2 points"); }
        double mx=0,my=0;
        for(size_t i=0;i<nx;i++){ mx+=x[i]; my+=y[i]; }
        mx/=nx; my/=ny;
        double num=0, denx=0, deny=0;
        for(size_t i=0;i<nx;i++){ double dx=x[i]-mx, dy=y[i]-my; num+=dx*dy; denx+=dx*dx; deny+=dy*dy; }
        double denom=sqrt(denx*deny);
        double r=0;
        if(denom>1e-12) r=num/denom; else r=0;
        /* clamp */
        if(r>1) r=1; if(r<-1) r=-1;
        sds out=sdscatprintf(sdsempty(),"{\"action\":\"correlation\",\"n\":%zu,\"r\":%.6g,\"r2\":%.6g}",nx,r,r*r);
        free(x); free(y);
        return out;
    }

    if (strcmp(action,"normalize")==0) {
        size_t n=0; sds err=NULL;
        double *data=stats_get_array(args,"data",&n,&err);
        if(!data){
            if(err) sdsfree(err);
            data=stats_get_array(args,"values",&n,&err);
            if(!data){ if(err) return err; return sdsnew("ERROR: 'data' array required for normalize"); }
        }
        if(err) sdsfree(err);
        const char *method=cJSON_GetStringValue(cJSON_GetObjectItem(args,"method"));
        if(!method||!method[0]) method="zscore";
        sds out=NULL;
        if(strcmp(method,"zscore")==0 || strcmp(method,"z")==0){
            double sum=0; for(size_t i=0;i<n;i++) sum+=data[i];
            double mean=sum/n;
            double var=0; for(size_t i=0;i<n;i++){ double d=data[i]-mean; var+=d*d; } var/=n;
            double sd=sqrt(var);
            out=sdscatprintf(sdsempty(),"{\"action\":\"normalize\",\"method\":\"zscore\",\"mean\":%.6g,\"stdev\":%.6g,\"data\":[",mean,sd);
            for(size_t i=0;i<n;i++){
                if(i) out=sdscat(out,",");
                double v = sd>1e-12 ? (data[i]-mean)/sd : 0;
                out=sdscatprintf(out,"%.6g",v);
            }
            out=sdscat(out,"]}");
        } else if(strcmp(method,"minmax")==0 || strcmp(method,"min_max")==0 || strcmp(method,"range")==0){
            double mn=data[0], mx=data[0];
            for(size_t i=0;i<n;i++){ if(data[i]<mn) mn=data[i]; if(data[i]>mx) mx=data[i]; }
            double range=mx-mn;
            out=sdscatprintf(sdsempty(),"{\"action\":\"normalize\",\"method\":\"minmax\",\"min\":%.6g,\"max\":%.6g,\"data\":[",mn,mx);
            for(size_t i=0;i<n;i++){
                if(i) out=sdscat(out,",");
                double v = range>1e-12 ? (data[i]-mn)/range : 0;
                out=sdscatprintf(out,"%.6g",v);
            }
            out=sdscat(out,"]}");
        } else {
            free(data);
            return sdscatprintf(sdsempty(),"ERROR: unknown normalize method '%s' (use zscore/minmax)",method);
        }
        free(data);
        return out;
    }

    if (strcmp(action,"percentile")==0 || strcmp(action,"quantile")==0) {
        size_t n=0; sds err=NULL;
        double *data=stats_get_array(args,"data",&n,&err);
        if(!data){
            if(err) sdsfree(err);
            data=stats_get_array(args,"values",&n,&err);
            if(!data){ if(err) return err; return sdsnew("ERROR: 'data' array required for percentile"); }
        }
        if(err) sdsfree(err);
        double p=50;
        cJSON *jp=cJSON_GetObjectItem(args,"p");
        if(!cJSON_IsNumber(jp)) jp=cJSON_GetObjectItem(args,"percentile");
        if(!cJSON_IsNumber(jp)) jp=cJSON_GetObjectItem(args,"q");
        if(cJSON_IsNumber(jp)) p=jp->valuedouble;
        if(p<0) p=0; if(p>100) p=100;
        double *sorted=(double*)malloc(n*sizeof(double));
        if(!sorted){ free(data); return sdsnew("ERROR: allocation failed"); }
        memcpy(sorted,data,n*sizeof(double));
        qsort(sorted,n,sizeof(double),stats_cmp_dbl);
        double rank = p/100.0 * (n - 1);
        size_t lo = (size_t)floor(rank);
        size_t hi = (size_t)ceil(rank);
        double val;
        if(lo==hi) val=sorted[lo];
        else {
            double frac = rank - lo;
            val = sorted[lo]*(1-frac) + sorted[hi]*frac;
        }
        sds out=sdscatprintf(sdsempty(),"{\"action\":\"percentile\",\"p\":%.6g,\"value\":%.6g,\"count\":%zu}",p,val,n);
        free(sorted); free(data);
        return out;
    }

    return sdscatprintf(sdsempty(),"ERROR: unknown stats action '%s' (use describe/histogram/correlation/normalize/percentile)",action);
}

static const alpha_tool_t tool_stats = {
    .name = "stats",
    .aliases = {"statistics","describe","histogram",NULL},
    .category = "analysis",
    .description = "Pure-C statistical analysis: describe (count/mean/median/min/max/variance/stdev), histogram (binned counts), correlation (Pearson r), normalize (zscore/minmax), percentile (quantile).",
    .schema_json = "{\"type\":\"function\",\"function\":{\"name\":\"stats\",\"description\":\"Pure-C statistical analysis: describe, histogram, correlation, normalize, percentile.\",\"parameters\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"describe\",\"histogram\",\"correlation\",\"normalize\",\"percentile\"],\"description\":\"Statistical operation\"},\"data\":{\"type\":\"string\",\"description\":\"JSON array string or array of numbers (e.g. \\\"[1,2,3]\\\" or [1,2,3])\"},\"values\":{\"type\":\"array\",\"items\":{\"type\":\"number\"},\"description\":\"alias for data\"},\"x\":{\"type\":\"array\",\"items\":{\"type\":\"number\"},\"description\":\"X values for correlation\"},\"y\":{\"type\":\"array\",\"items\":{\"type\":\"number\"},\"description\":\"Y values for correlation\"},\"bins\":{\"type\":\"integer\",\"description\":\"Number of bins for histogram (1-256)\"},\"method\":{\"type\":\"string\",\"enum\":[\"zscore\",\"minmax\"],\"description\":\"Normalization method\"},\"p\":{\"type\":\"number\",\"description\":\"Percentile 0-100\"},\"percentile\":{\"type\":\"number\",\"description\":\"alias for p\"}},\"required\":[]}}}",
    .run = tool_stats_run
};
