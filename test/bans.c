#include "../include/parser.h"

int main(){
	char str[] = "/MSG server cara anchoa";
	iniBigBrother(NULL);
	printf("%s\n", str);
	printf("%d\n", bigBrother(str));
	freeBigBrother();
}