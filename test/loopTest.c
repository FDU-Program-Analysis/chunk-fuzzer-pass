// clang -O0 -emit-llvm loopTest.c -c -o loopTest.bc
// llvm-dis loopTest.bc -o -
// opt -load-pass-plugin ./libLoopHandlingPass.so -passes=loop-handling-pass ../test/loopTest.ll

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <sanitizer/dfsan_interface.h>

void foo() {
    for(int i = 0; i < 10; ++i)
        printf("%d",i);
}

int main()
{
	foo();
	FILE *fp;
	fp = fopen("file", "rb");
	char ch;
	char buffer[10];
	char dst[10];
	for (int i = 0; i < 4 ; ++i) {
		fread(buffer, sizeof(char), 2, fp);
		strcpy(dst, buffer);
		if ( (dst[0]-'0') %3 == 0 )
			printf("%s ", dst);
	}
	return 0;
}
