#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

void main(int argc, char **argv){

	char jsonForDB[80];

	memset(jsonForDB, 0, sizeof(jsonForDB)/sizeof(jsonForDB));
	strcat(jsonForDB, "{\"fileName\":\"");
/*	strcat(jsonForDB, outputFilePath);
	strcat(jsonForDB, "\", \"hashValue\":\"");
	strcat(jsonForDB, hashForDB);
	strcat(jsonForDB, "\"}");*/
	printf("%s", jsonForDB);



}
