#include "../src/telegram.c"
int main(int argc, char **argv){
    setenv("ALPHA_ROOT", argv[1], 1);
    alarm(20);
    sds t = voice_transcribe("/tmp/vt2.ogg");
    printf("RESULT = %s\n", t ? t : "(null)");
    return 0;
}
