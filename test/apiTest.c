#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../dfsan_rt/dfsan_interface.h"

FILE *fp;

void offset_test(){
    char buffer[10];
    for(int i=0;i<4;i++){
        fread(buffer,sizeof(char),1,fp);
        int c = buffer[0]-'0';
        fseek(fp,c,SEEK_CUR);
    }
}

void cmp_test(){
    char buf1[10];
    char buf2[10];
    for(int i=0;i<3;i++){
        fread(buf1, sizeof(char),2,fp);
        buf1[2]='\0';
        dfsan_label buffer1 = dfsan_read_label(buf1,sizeof(buf1));
        fread(buf2, sizeof(char),2,fp);
        buf2[2]='\0';
        dfsan_label buffer2 = dfsan_read_label(buf2,sizeof(buf2));
        printf("%s %s\n",buf1,buf2);
        printf("%d %d\n",buffer1,buffer2);
        strcmp(buf1,"12");
        strcmp(buf1,buf2);
    }
}

void len0_test(){
    char buf1[10];
    char lenbuf[10];
    int len;
    for(int i=0;i<10;i++){
        buf1[i]='\0';
        lenbuf[i]='\0';
    }
    for(int i=0;i<3;i++){
        fread(lenbuf,sizeof(char),1,fp);
        len = lenbuf[0]-'0';
        fread(buf1, sizeof(char),len,fp);
        dfsan_label buffer1 = dfsan_read_label(buf1,sizeof(buf1));
        printf("%s %d\n",buf1,buffer1);
    }
}

int main()
{
 	fp = fopen("file", "rb");
    
    len0_test();

    fclose(fp);
	return 0;
}