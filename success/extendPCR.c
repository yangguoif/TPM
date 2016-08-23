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


//#define DEBUG 0
/*#define DBG(message,tResult) if(DEBUG) {fprintf(“(Line %d, %s) %s returned 0x%08x. %s.\n", __LINE__, __func__, message, tResult, trspi_Error_String(tResult));}*/

#define DBG(message, tResult) printf("Line%d, %s)%s returned 0x%08x. %s.\n", __LINE__, __func__, message, tResult, (char *)Trspi_Error_String(tResult))


void printMenu()
{
	printf("\nChangePCRn Help Menu:\n");
	printf("\t-p PCR register to extend (0-23)\n");
	printf("\t-v value to be extended into PCR(abc..)\n");
	printf("\tNote: -v argument is optional and a default value will be used if no value is provided\n");
	printf("\tExample: ChangePCRn -p 10 -v abcdef\n");
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
	TSS_HPCRS hPcrs;
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

	UINT32 PCR_result_length;
	BYTE *Final_PCR_Value;
	BYTE valueToExtend[250];
	int count = 0;
	int pcrToExtend = 0;
	memset(valueToExtend,0,250);
	// Display each command line argument.
	printf("\n Command line arguments:\n");
	for(count = 0; count < argc; count++){
		printf(" argv[%d] %s\n", count, argv[count]);
	}
	// Examine command line arguments.
	if(argc >= 3){
		if(strcmp(argv[1],"-p") == 0){
			pcrToExtend = atoi(argv[2]);
			if(pcrToExtend < 0 || pcrToExtend > 23){
				printMenu();
				return 0;
			}
			if(argc == 5){
				if(strcmp(argv[3], "-v") == 0){
					memcpy(valueToExtend, argv[4], strlen(argv[4]));
				}
			}else{
				//use default value
				memcpy(valueToExtend, "abcdefghijklmnopqrst", 20);
			}
		}		
	}else{
		printMenu();
		return 0;
	}
	result = Tspi_TPM_PcrExtend(hTPM, pcrToExtend, 20, (BYTE *)valueToExtend, NULL, &PCR_result_length, &Final_PCR_Value);
	DBG("Extended the PCR", result);




	//-----Postlude
	Tspi_Context_Close(hContext);
	Tspi_Context_FreeMemory(hContext, NULL);
	// this frees memory that was automatically allocated for you
	Tspi_Context_Close(hContext);
	//-----------	
	return 0;
}
