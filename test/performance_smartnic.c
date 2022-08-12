#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>

#include "../xmss.h"
#include "../params.h"
#include "../randombytes.h"

#ifndef PERFORMANCE_TYPE
#define PERFORMANCE_TYPE "generate"
#endif


#ifdef XMSSMT
#define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
#else
#define XMSS_PARSE_OID xmss_parse_oid
#define XMSS_STR_TO_OID xmss_str_to_oid
#define XMSS_KEYPAIR xmss_keypair
#define XMSS_SIGN xmss_sign
#define XMSS_SIGN_OPEN xmss_sign_open
#endif

#ifndef XMSS_VARIANT
#ifdef XMSSMT
#define XMSS_VARIANT "XMSSMT-SHA2_20/2_256"
#else
#define XMSS_VARIANT "XMSS-SHA2_10_256"
#endif
#endif

static double average_time(double timeArray[])
{
    int n = sizeof(timeArray);
    int i;
    double sum, avg;

    for (i = 0; i < n; ++i) {
        sum += timeArray[i];
    }

    avg = sum / n;

    return avg;
}


static double speed_test(int xmss_mlen, int xmss_signatures, char *performance_type)
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    xmss_params params;
    uint32_t oid;
    int ret = 0;
    int i;

    if (XMSS_STR_TO_OID(&oid, XMSS_VARIANT)) {
#ifdef XMSSMT
        printf("XMSSMT variant %s not recognized!\n", XMSS_VARIANT);
#else
        printf("XMSS variant %s not recognized!\n", XMSS_VARIANT);
#endif
        return -1;
    }
    XMSS_PARSE_OID(&params, oid);

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    unsigned char *m = malloc(xmss_mlen);
    unsigned char *sm = malloc(params.sig_bytes + xmss_mlen);
    unsigned char *mout = malloc(params.sig_bytes + xmss_mlen);
    unsigned long long smlen;
    unsigned long long mlen;

    unsigned long long t0, t1;
    unsigned long long *t = malloc(sizeof(unsigned long long) * xmss_signatures);
    struct timespec start, stop, total_start, total_stop;
    double result;
    double time[xmss_signatures];
    double avg_time, gross_time, generating_key_pair_time, creating_signature_time, verifying_signature_time;

    randombytes(m, xmss_mlen);

    printf("Benchmarking variant %s\n", XMSS_VARIANT);

    printf("Generating keypair.. ");

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    XMSS_KEYPAIR(pk, sk, oid);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);
    result = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;
    generating_key_pair_time = result;

    printf("took %lf us (%.2lf sec) \n", generating_key_pair_time, generating_key_pair_time / 1e6);

    printf("Creating %d signatures..\n", xmss_signatures);

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &total_start);
    for (i = 0; i < xmss_signatures; i++) {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
        XMSS_SIGN(sk, sm, &smlen, m, xmss_mlen);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);
        result = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;
        time[i]= result;
    }
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &total_stop);
    gross_time = (total_stop.tv_sec - total_start.tv_sec) * 1e6 + (total_stop.tv_nsec - total_start.tv_nsec) / 1e3;
    creating_signature_time = gross_time/1e6;

    print_results(t, xmss_signatures);
    avg_time = average_time(time);

    printf("Total time taken to create all signature %.2lf sec.\n", gross_time/1e6 );
    printf("Average time taken to create each signature %.2lf sec.\n\n\n", avg_time/1e6 );


    printf("Verifying %d signatures..\n", xmss_signatures);

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &total_start);
    for (i = 0; i < xmss_signatures; i++) {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
        ret |= XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);
        result = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;
        time[i]= result;
    }
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &total_stop);
    gross_time = (total_stop.tv_sec - total_start.tv_sec) * 1e6 + (total_stop.tv_nsec - total_start.tv_nsec) / 1e3;
    verifying_signature_time = gross_time;
    print_results(t, xmss_signatures);

    avg_time = average_time(time);
    printf("Total time taken to verify all signature %.2lf sec.\n", gross_time/ 1e3 );
    printf("Average time taken to verify each signature %.2lf sec.\n\n", avg_time/ 1e3 );

    if (ret) {
        printf("DETECTED VERIFICATION ERRORS!\n");
    }

    printf("Signature size: %d (%.2f KiB)\n", params.sig_bytes, params.sig_bytes / 1024.0);
    printf("Public key size: %d (%.2f KiB)\n", params.pk_bytes, params.pk_bytes / 1024.0);
    printf("Secret key size: %llu (%.2f KiB)\n", params.sk_bytes, params.sk_bytes / 1024.0);

    free(m);
    free(sm);
    free(mout);
    free(t);

    if(strcmp(performance_type, "create") == 0) {
        return creating_signature_time/ 1e3;
    } else if (strcmp(performance_type, "generate") == 0) {
        return generating_key_pair_time;
    } else if (strcmp(performance_type, "verify") == 0){
        return verifying_signature_time/ 1e3;
    }else if (strcmp(performance_type, "create_and_verify") == 0){
        return verifying_signature_time+creating_signature_time/ 1e3;
    } else{
        return 0;
    }
}


int main()
{
    FILE * fp;

    fp = fopen ("result_smartnic.csv", "w+");
    fprintf(fp,"Message size (bytes), Time\n");

    int i;
    int j = 0;

    for (i = 0; i < 12; ++i) {
        printf("iteration %d\n", j);
        double time = speed_test(pow(2,i), 16, PERFORMANCE_TYPE);
        printf("%f", pow(2,i));
        fprintf(fp,"%d , %f\n", (int)pow(2,i), time);
        ++j;
        printf("\n\n\n");
        if(j==50){
            break;
        }
    }
    fclose(fp);
    return 0;
}