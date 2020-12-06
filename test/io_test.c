#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../dfsan_rt/dfsan_interface.h"

#include <sys/types.h>    
#include <sys/stat.h>    
#include <fcntl.h>
#include <unistd.h>

/*
../install/test-clang loopTest.c -o loopTest

./loopTest 2>&1                             
0123456789fp_label: 0
[]
buffer_label: 4
[TagSeg { sign: false, begin: 0, end: 1 }, TagSeg { sign: false, begin: 1, end: 2 }]
dst_label: 4
[TagSeg { sign: false, begin: 0, end: 1 }, TagSeg { sign: false, begin: 1, end: 2 }]
34 
buffer_label: 9
[TagSeg { sign: false, begin: 2, end: 3 }, TagSeg { sign: false, begin: 3, end: 4 }]
dst_label: 9
[TagSeg { sign: false, begin: 2, end: 3 }, TagSeg { sign: false, begin: 3, end: 4 }]
buffer_label: 14
[TagSeg { sign: false, begin: 4, end: 5 }, TagSeg { sign: false, begin: 5, end: 6 }]
dst_label: 14
[TagSeg { sign: false, begin: 4, end: 5 }, TagSeg { sign: false, begin: 5, end: 6 }]
buffer_label: 19
[TagSeg { sign: false, begin: 6, end: 7 }, TagSeg { sign: false, begin: 7, end: 8 }]
dst_label: 19
[TagSeg { sign: false, begin: 6, end: 7 }, TagSeg { sign: false, begin: 7, end: 8 }]

*/


void foo() {
    for(int i = 0; i < 10; ++i)
        printf("%d\n",i);
}

void stat_test() {
  struct stat buf;
  stat("file", &buf);
  printf("file size = %ld\n", buf.st_size);
  dfsan_label stat_label = dfsan_read_label(&buf.st_size,sizeof(buf.st_size));
  printf("stat_label: %d\n", stat_label);
  dfsan_dump_label(stat_label);
}

void fstat_test(int fd){
    struct stat buf;
    fstat(fd,&buf);
    printf("file size = %ld\n", buf.st_size);
    dfsan_label stat_label = dfsan_read_label(&buf.st_size,sizeof(buf.st_size));
    printf("stat_label: %d\n", stat_label);
    dfsan_dump_label(stat_label);
}

void fread_test(){
  char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
		fread(buffer, sizeof(char), 2, fp);
		strcpy(dst, buffer);
		if ( (dst[0]-'0') %3 == 0 )
			printf("%s \n", dst);
		dfsan_label buffer_label = dfsan_read_label(buffer,sizeof(buffer));
		dfsan_label dst_label = dfsan_read_label(dst,sizeof(dst));
		printf("buffer_label: %d\n", buffer_label);
		dfsan_dump_label(buffer_label);
		printf("dst_label: %d\n", dst_label);
		dfsan_dump_label(dst_label);
	}
}

void read_test(){
  char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
    read(fd,buffer,sizeof(char)*2);
		strcpy(dst, buffer);
		if ( (dst[0]-'0') %3 == 0 )
			printf("%s \n", dst);
		dfsan_label buffer_label = dfsan_read_label(buffer,sizeof(buffer));
		dfsan_label dst_label = dfsan_read_label(dst,sizeof(dst));
		printf("buffer_label: %d\n", buffer_label);
		dfsan_dump_label(buffer_label);
		printf("dst_label: %d\n", dst_label);
		dfsan_dump_label(dst_label);
	}
}

void pread_test(){
  char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
    pread(fd,buffer,sizeof(char)*2,2*i);
    // 利用fgetc的情况下出现了一个bug 在tag的追加的时候出现了问题 一般的测试用例下没有问题
    // buffer[0] = fgetc(fp);
    // buffer[1] = fgetc(fp);
    gets(buffer);
		strcpy(dst, buffer);
		if ( (dst[0]-'0') %3 == 0 )
			printf("%s \n", dst);
		dfsan_label buffer_label = dfsan_read_label(buffer,sizeof(buffer));
		dfsan_label dst_label = dfsan_read_label(dst,sizeof(dst));
		printf("buffer_label: %d\n", buffer_label);
		dfsan_dump_label(buffer_label);
		printf("dst_label: %d\n", dst_label);
		dfsan_dump_label(dst_label);
	}
}

void fgetc_test(){
  char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
    buffer[0] = fgetc(fp);
    buffer[1] = fgetc(fp);
    // gets(buffer);
		strcpy(dst, buffer);
		if ( (dst[0]-'0') %3 == 0 )
			printf("%s \n", dst);
		dfsan_label buffer_label = dfsan_read_label(buffer,sizeof(buffer));
		dfsan_label dst_label = dfsan_read_label(dst,sizeof(dst));
		printf("buffer_label: %d\n", buffer_label);
		dfsan_dump_label(buffer_label);
		printf("dst_label: %d\n", dst_label);
		dfsan_dump_label(dst_label);
	}
}

void fgetc_bug_test(){
  // 利用fgetc的情况下出现了一个bug 在tag的追加的时候出现了问题 一般的测试用例下没有问题
  char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
    buffer[2*i] = fgetc(fp);
    buffer[2*i+1] = fgetc(fp);
    // gets(buffer);
		strcpy(dst, buffer);
		if ( (dst[0]-'0') %3 == 0 )
			printf("%s \n", dst);
		dfsan_label buffer_label = dfsan_read_label(buffer,sizeof(buffer));
		dfsan_label dst_label = dfsan_read_label(dst,sizeof(dst));
		printf("buffer_label: %d\n", buffer_label);
		dfsan_dump_label(buffer_label);
		printf("dst_label: %d\n", dst_label);
		dfsan_dump_label(dst_label);
	}
}

// 用不了 c99标准
// void gets_test(){
//   char ch;
// 	char buffer[10];
// 	char dst[10];
// 	for (int i = 0; i < 4 ; ++i) {
//     gets(buffer);
// 		strcpy(dst, buffer);
// 		if ( (dst[0]-'0') %3 == 0 )
// 			printf("%s \n", dst);
// 		dfsan_label buffer_label = dfsan_read_label(buffer,sizeof(buffer));
// 		dfsan_label dst_label = dfsan_read_label(dst,sizeof(dst));
// 		printf("buffer_label: %d\n", buffer_label);
// 		dfsan_dump_label(buffer_label);
// 		printf("dst_label: %d\n", dst_label);
// 		dfsan_dump_label(dst_label);
// 	}
// }

int main()
{
	foo();
  int fd;
  FILE *fp;
 	fp = fopen("file", "rb");
  // open
  // fd = open("file",O_RDWR);
  // fp = fdopen(fd, "r");
	dfsan_label fp_label= dfsan_read_label(fp, sizeof(fp));
	printf("fp_label: %d\n", fp_label);
	dfsan_dump_label(fp_label);

	fread_test();

  fclose(fp);
	return 0;
}
