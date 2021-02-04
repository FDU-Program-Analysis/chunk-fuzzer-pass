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

int main()
{
 	fp = fopen("file", "rb");
    
    cmp_test();

    fclose(fp);
	return 0;
}