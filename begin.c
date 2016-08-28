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

//extend a PCR's value
//int pcrToExtend: the PCR number which is gonna be extend
//BYTE *valueToExtend: the value used to extend, in this program, it is the hash value of the hashed file
void extendPCR(TSS_HCONTEXT hContext, int pcrToExtend, BYTE *valueToExtend)
{
	TSS_HTPM hTPM = 0;
	TSS_RESULT result;
	result = Tspi_Context_Connect(hContext, NULL);
	// Get the TPM handle
	result=Tspi_Context_GetTpmObject(hContext, &hTPM); 
	UINT32 PCR_result_length;
	BYTE *Final_PCR_Value;
	result = Tspi_TPM_PcrExtend(hTPM, pcrToExtend, 20, valueToExtend, NULL, &PCR_result_length, &Final_PCR_Value);
	DBG("Extended the PCR", result);
}

//reset a PCR to default value
//int pcrToReset: the PCR number which is going to be reset
void resetPCR(TSS_HCONTEXT hContext, int pcrToReset)
{	
	TSS_HTPM hTPM = 0;
	TSS_RESULT result;
	TSS_HPCRS hPcrs;
	result=Tspi_Context_GetTpmObject(hContext, &hTPM);
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS, 0, &hPcrs);
	result = Tspi_PcrComposite_SelectPcrIndex(hPcrs, pcrToReset);
	result = Tspi_TPM_PcrReset(hTPM, hPcrs);
	DBG("Reset the PCR", result);
}

void readPCR(TSS_HCONTEXT hContext, UINT32 pcrToRead, BYTE pcrValue[20]){
	BYTE *digest;
	TSS_RESULT result;
	TSS_HTPM hTPM = 0;
	// Pick the TPM you are talking to in this case the system TPM (which you connect to with “NULL”)
	result = Tspi_Context_Connect(hContext, NULL);
	// Get the TPM handle
	result=Tspi_Context_GetTpmObject(hContext, &hTPM);
	BYTE *rgbPcrValue;
	UINT32 ulPcrValueLength=20;
	int i, j;

//	this is for reading all the PCRs
	for(j=0; j<24; ++j){
		result = Tspi_TPM_PcrRead(hTPM, j, &ulPcrValueLength, &rgbPcrValue);
		printf("PCR %02d",j);
		for(i=0 ; i<19;++i){
			printf("%02x",*(rgbPcrValue+i));
		}
		printf("\n");
	}

	result = Tspi_TPM_PcrRead(hTPM, pcrToRead, &ulPcrValueLength, &digest);
	memcpy(pcrValue,digest,20);
	DBG("Read the PCR", result);
}

//hash an array of BYTE (which is the file which is gonna be hashed). 
//BYTE *content: the array of BYTE which is gonna be hashed
//BYTE hash[20]: the hash result
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

//get the size of the file which is gonna be hashed, in BYTE.
long getFileSize(char *filePath){
	long siz = 0;
	FILE *fp = fopen(filePath, "rb");
	if(fp){
		fseek(fp, 0, SEEK_END);
		siz = ftell(fp);	
	}
	fclose(fp);
	return siz;
}

//read the file which is gonna be hashed BYTE by BYTE
//BYTE *s: the target BYTE array to store the content of being read
void readFile(char *filePath, long fileSize, BYTE *s){
	FILE *fp = fopen(filePath, "rb");
	fread(s, sizeof(BYTE), fileSize, fp);
	fclose(fp);
}

int main(int argc, char **argv)
{
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
	
	int i;	//an int for controling for loop
	int changeFlag = 1;	//flag for comparison of PCR16 and PCR23
	char *filePath = "/home/yg115/test/testForSysdig/trace.scap71";
	long size = getFileSize(filePath);
	BYTE s[size];	//an BYTE array to store the content of file
	long size1;	//for test loop	
	BYTE s1[size];	//for test loop
	readFile(filePath, size, s);
	BYTE hash[20];	//an BYTE array to store the hash result of the content in BYTE s[]
	BYTE hash1[20];	//for test loop
	BYTE pcrValue[20];	//an BYTE array to store the pcr value read out from a PCR by readPCR()
	BYTE pcrValue1[20];	//for the test loop PCR
	HashThis(hContext, &s, size, &hash);

	
	for(i=0 ; i<19;++i){	//print the hash value
		printf("%02x",*(hash+i));
	}
	printf("\n");

	resetPCR(hContext, 23);
	extendPCR(hContext, 23, hash);
	readPCR(hContext, 23, pcrValue);	

	while(1){
		size1 = getFileSize(filePath);
		readFile(filePath, size1, s1);
		HashThis(hContext, &s1, size1, &hash1);

		resetPCR(hContext, 16);
		extendPCR(hContext, 16, hash1);
		readPCR(hContext, 16, pcrValue1);
		i = memcmp(pcrValue, pcrValue1, 20);
		changeFlag = memcmp(pcrValue, pcrValue1, 20);
		if(changeFlag != 0){
			printf("changed");
			break;
		}
	}


/*	
	//-------------------print the pcr value read out by readPCR()
	printf("PCR %02d : ", 23);
	for(i=0 ; i<19;++i){
		printf("%02x",*(pcrValue+i));
	}
	printf("\n");
	//--------------------------------------------------
*/
	//-----Postlude
	Tspi_Context_Close(hContext);
	Tspi_Context_FreeMemory(hContext, NULL);
	// this frees memory that was automatically allocated for you
	Tspi_Context_Close(hContext);
	//-----------	
	return 0;
}
