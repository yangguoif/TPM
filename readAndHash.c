#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

#define DBG(message, tResult) printf("Line%d, %s)%s returned 0x%08x. %s.\n", __LINE__, __func__, message, tResult, (char *)Trspi_Error_String(tResult))
#define BUFFERSIZE 20

/*
void readFile(char *filePath, long fileSize, BYTE *s){
	FILE *fp = fopen(filePath, "rb");
	fread(s, sizeof(BYTE), fileSize, fp);
	fclose(fp);
}
*/

void HashThis(TSS_HCONTEXT hContext, BYTE *content, UINT32 contentSize, BYTE hash[20]){
	TSS_RESULT result;
	BYTE *digest;
	UINT32 digestLen;
	TSS_HHASH hHashOfESSKey;
	BYTE initialHash[20];
	memset(initialHash,0,20);
	// Create a generic Hash object
	result=Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHashOfESSKey);
	// Hash the data using SHA1
	result=Tspi_Hash_UpdateHashValue(hHashOfESSKey, contentSize, content);
	result=Tspi_Hash_GetHashValue(hHashOfESSKey, &digestLen, &digest);
	DBG("Get the hashed result", result);
	memcpy(hash,digest,20);
}

void main(int argc, char **argv){
	//-----Preamble
	TSS_HCONTEXT hContext=0;
	TSS_HTPM hTPM = 0;
	TSS_RESULT result;
	TSS_HKEY hSRK = 0;
	TSS_HPOLICY hSRKPolicy=0;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	//TSS_HPCRS hPcrs;
	BYTE wks[20]; // Place to put the well known secret
	memset(wks,0,20); // Set wks to the well known secret of 20 bytes of all zeros
	// Pick the TPM you are talking to in this case the system TPM (which you connect to with “NULL”)
	result = Tspi_Context_Create(&hContext);
	result = Tspi_Context_Connect(hContext, NULL);
	// Get the TPM handle
	result=Tspi_Context_GetTpmObject(hContext, &hTPM); 
	//Get the SRK handle
	result=Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	//Get the SRK policy
	result=Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
	//Set the SRK policy to be the well known secret
	result=Tspi_Policy_SetSecret(hSRKPolicy,TSS_SECRET_MODE_SHA1,20, wks); 
	// Note: TSS_SECRET_MODE_SHA1 says “Don’t hash this. Just use the 20 bytes as is.
	//-----------------

	char *inputFilePath = "/home/yg115/test/testForSysdig/trace.scap71";
	char *outputFilePath[80];	//output file path for the content in buffer, the new
							//file will be created and the fileNum will be added at the back
	int i;	
	BYTE bufferHash[20];
	int fileNum = 1;
	char stringNum[25];
	BYTE buffer[BUFFERSIZE];
	FILE *fp = fopen(inputFilePath, "rb");
	if(setvbuf(fp, buffer, _IOFBF, BUFFERSIZE) != 0)
		printf("failed to setup buffer for input file");
	else{
		fread(buffer, sizeof(buffer), 1, fp);
		HashThis(hContext, &buffer, BUFFERSIZE, &bufferHash);
		snprintf(stringNum, 25, "%d", fileNum);	//change fileNum(int) to char for strcat()
		fileNum++;
		strcat(outputFilePath, "/home/yg115/test/generatedFile/log");
		strcat(outputFilePath, stringNum);
		FILE *fpo = fopen(outputFilePath, "wb");
		fwrite(buffer, sizeof(buffer), 1, fpo);
		fflush(fpo);
		fclose(fpo);
		for(i=0 ; i<19;++i){	//print the hash value
			printf("%02x",*(bufferHash+i));
		}
	}

}
