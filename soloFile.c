#define __USE_C99_MATH
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <regex.h>
#include <sys/sem.h> 

#include <bson.h>
#include <bcon.h>
#include <mongoc.h>

#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

#define DBG(message, tResult) printf("Line%d, %s)%s returned 0x%08x. %s.\n", __LINE__, __func__, message, tResult, (char *)Trspi_Error_String(tResult))

union semun  
{  
    int val;  
    struct semid_ds *buf;  
    unsigned short *arry;  
};
//#define path /home/yg115/test/generatedFile/

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
	//DBG("Extended the PCR", result);
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
	//DBG("Reset the PCR", result);
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
	result = Tspi_TPM_PcrRead(hTPM, pcrToRead, &ulPcrValueLength, &digest);
	memcpy(pcrValue,digest,20);
	//DBG("Read the PCR", result);
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
	//DBG("Get the hashed result", result);
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

char** getFileNameArray(const char *path, int *fileCount)  
{  
    int count = 0;  
    char **fileNameList = NULL;  
    struct dirent* ent = NULL;  
    DIR *pDir;  
    char dir[512];  
    struct stat statbuf;  
  
    if ((pDir = opendir(path)) == NULL)  
    {  
        printf("Cannot open directory:%s\n", path);  
        return NULL;  
    }  
    while ((ent = readdir(pDir)) != NULL)  
    {
        snprintf(dir, 512, "%s%s", path, ent->d_name);  
        lstat(dir, &statbuf);    
        if (!S_ISDIR(statbuf.st_mode))  
        {  
            count++;  
        }  
    }   
    closedir(pDir);

 	
	
    if ((fileNameList = (char**) malloc(sizeof(char*) * count)) == NULL)  
    {  
        printf("Malloc heap failed!\n");  
        return NULL;  
    }  

    if ((pDir = opendir(path)) == NULL)  
    {  
        printf("Cannot open directory:%s\n", path);  
        return NULL;  
    }  
 
    int i;  
    for (i = 0; (ent = readdir(pDir)) != NULL && i < count;)  
    {  
        if (strlen(ent->d_name) <= 0)  
        {  
            continue;  
        }   
        snprintf(dir, 512, "%s/%s", path, ent->d_name);    
        lstat(dir, &statbuf);   
        if (!S_ISDIR(statbuf.st_mode))  
        {  
            if ((fileNameList[i] = (char*) malloc(strlen(ent->d_name) + 1))  
                    == NULL)  
            {  
                printf("Malloc heap failed!\n");  
                return NULL;  
            }  
            memset(fileNameList[i], 0, strlen(ent->d_name) + 1);  
            strcpy(fileNameList[i], ent->d_name);  
            i++;  
        }  
    }
    closedir(pDir);  
  
    *fileCount = count;  
    return fileNameList;  
}

//read the file which is gonna be hashed BYTE by BYTE
//BYTE *s: the target BYTE array to store the content of being read
void readFile(char *filePath, long fileSize, BYTE *s){
	FILE *fp = fopen(filePath, "rb");
	fread(s, sizeof(BYTE), fileSize, fp);
	fclose(fp);
}

static int set_semvalue(int sem_id)  //initialize semaphore
{  
    union semun sem_union;  
  
    sem_union.val = 1;  
    if(semctl(sem_id, 0, SETVAL, sem_union) == -1)  
        return 0;  
    return 1;  
}  
  
static void del_semvalue(int sem_id)  //delete semaphore
{  
    union semun sem_union;  
  
    if(semctl(sem_id, 0, IPC_RMID, sem_union) == -1)  
        fprintf(stderr, "Failed to delete semaphore\n");  
}  
  
static int semaphore_p(int sem_id)  
{   
    struct sembuf sem_b;  
    sem_b.sem_num = 0;  
    sem_b.sem_op = -1;//P()  
    sem_b.sem_flg = SEM_UNDO;  
    if(semop(sem_id, &sem_b, 1) == -1)  
    {  
        fprintf(stderr, "semaphore_p failed\n");  
        return 0;  
    }  
    return 1;  
}  
  
static int semaphore_v(int sem_id)  
{   
    struct sembuf sem_b;  
    sem_b.sem_num = 0;  
    sem_b.sem_op = 1;//V()  
    sem_b.sem_flg = SEM_UNDO;  
    if(semop(sem_id, &sem_b, 1) == -1)  
    {  
        fprintf(stderr, "semaphore_v failed\n");  
        return 0;  
    }  
    return 1;  
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
	
	//---------------------initialize mongodb connection
	mongoc_client_t *client;
	mongoc_collection_t *collection;
	
	

	mongoc_init ();

	client = mongoc_client_new ("mongodb://localhost:27017/");
	collection = mongoc_client_get_collection (client, "logHash", "testHash");
	
	//---------------------------

	//-----------------initializing shared memory for the communication between check code and this code
	void *shm = NULL;	//the first memory address in this code for shared memory
	int shmid;	//shared memory id
	bool *checkFlag = NULL;	//a ptr point to the boolean value stored in the shared memory
	shmid = shmget((key_t)1234, sizeof(checkFlag), 0666|IPC_CREAT);
	if(shmid == -1)	//initializing sccuess?
    	{  
        	fprintf(stderr, "shmget failed\n");  
        	exit(EXIT_FAILURE);  
    	}
	shm = shmat(shmid, 0, 0);  //match shared memory to current process
	if(shm == (void*)-1)  
	{  
		fprintf(stderr, "shmat failed\n");  
		exit(EXIT_FAILURE);  
	}  
	printf("\nMemory attached at %X\n", (int)shm); 
	checkFlag = (bool*) shm;

	//-----------------initializing shared memory ends
	//------------------initialize semaphre
	int sem_id = semget((key_t)1235, 1, 0666 | IPC_CREAT); 
	//-----------------------
	int i;	//an int for controling for loop
	int changeFlag = 1;	//flag for comparison of PCR16 and PCR23
	const char *path = "/home/yg115/test/generatedFile/";
	int fileCount = 0;
	BYTE hash1[20];	//for test loop
	BYTE pcrValue[20];	//an BYTE array to store the pcr value read out from a PCR by readPCR()
	BYTE pcrValue1[20];	//for the test loop PCR
	BYTE pcrValue2[20];	//for single file check
	BYTE pcrValue3[20];
		
	int cflags = REG_EXTENDED;
	int status;
	regmatch_t pmatch[1];
	const size_t nmatch = 1;
	regex_t reg;
	const char * pattern = "\\Value\" : \"([0-9]|[a-z])+";

	while(1){
		resetPCR(hContext, 16);
		fileCount = 0;
		char** fileNameArray = getFileNameArray(path, &fileCount);
		printf("fileCount is ....%d\n", fileCount);
		for(int i = 1; i <= fileCount; i++){
        		//char *fileDir = *(fileNameArray+i);	
			char fileDir[100];
			sprintf(fileDir, "%s%d", path, i);
			//printf("\n i is %d\n", i);
			//printf("\nthis is the current file path....%s\n", fileDir);
        		long size1 = getFileSize(fileDir);
			BYTE s1[size1];
			readFile(fileDir, size1, s1);
			HashThis(hContext, &s1, size1, &hash1);
			extendPCR(hContext, 16, hash1);

			printf("file path....%s     pcrvalue...", fileDir);
			readPCR(hContext, 16, pcrValue2);
			for(int j=0 ; j<19;++j){				
				printf("%02x",*(pcrValue2+j));
			}
			printf("\n");
    		}

	
		readPCR(hContext, 16, pcrValue1);
		readPCR(hContext, 23, pcrValue);

		printf("\n pcr16 :");
		for(i=0 ; i<19;++i){			
			printf("%02x",*(pcrValue1+i));
		}

		printf("\n pcr23 :");
		for(i=0 ; i<19;++i){				
			printf("%02x",*(pcrValue+i));
		}


		i = memcmp(pcrValue, pcrValue1, 20);
		changeFlag = memcmp(pcrValue, pcrValue1, 20);

		printf("out of if....%d\n", *checkFlag);
		if(!semaphore_p(sem_id))  
           			exit(EXIT_FAILURE);
		if(*checkFlag == true){
			printf("in if.....%d\n", *checkFlag);
			*checkFlag = false;
			if(!semaphore_v(sem_id))  
           			exit(EXIT_FAILURE);
			continue;
		}
		if(!semaphore_v(sem_id))  
           			exit(EXIT_FAILURE);

		if(changeFlag != 0){
			printf("\nchanged\n");

			resetPCR(hContext, 16);
			for(int i = 1; i <= fileCount; i++){
				char fileDir[100];
				sprintf(fileDir, "%s%d", path, i);
				//printf("\n.....this is the current file path....%s\n", fileDir);
				long size1 = getFileSize(fileDir);
				BYTE s1[size1];
				readFile(fileDir, size1, s1);
				HashThis(hContext, &s1, size1, &hash1);
				extendPCR(hContext, 16, hash1);
				readPCR(hContext, 16, pcrValue3);

				char *curBuffer1 = (char *)malloc(sizeof(char)*40);
				char *curBuffer1Mark = curBuffer1;
				for(int j=0 ; j<19;++j){				
					sprintf(curBuffer1, "%02x", (unsigned char)pcrValue3[j]);
					curBuffer1 += 2;
				}
				printf("formed char from byte: %s\n", curBuffer1Mark);

				mongoc_cursor_t *cursor;
				const bson_t *doc;
				bson_t *query;
				char *strMongo;
				query = bson_new ();

				BSON_APPEND_UTF8 (query, "fileName", fileDir);

    				cursor = mongoc_collection_find (collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
				mongoc_cursor_next (cursor, &doc);
				
				strMongo = bson_as_json (doc, NULL);
				regcomp(&reg, pattern,cflags);
				status = regexec(&reg, strMongo, nmatch, pmatch, 0);
				if(status == REG_NOMATCH)
					printf("No match");
				else{
					char* curBuffer = (char *)malloc(sizeof(char)*40);
					int j = 0;
					for(int i = pmatch[0].rm_so + 10; i < pmatch[0].rm_eo; ++i){
						//putchar(strMongo[i]);
						*(curBuffer+j) = strMongo[i];
						j++;
						
					}
					*(curBuffer+j) = '\0';
					printf("curBuffer.....%s\n",curBuffer);

					if(memcmp(curBuffer, curBuffer1Mark, 20) != 0){
						printf("file %d is changed", i);
						bson_free (strMongo);
						regfree(&reg);
						bson_destroy (query);
						mongoc_cursor_destroy (cursor);
						free(curBuffer);
						free(curBuffer1Mark);
						break;					
					}
					free(curBuffer);
					free(curBuffer1Mark);
				}
				printf ("from mongo db%s\n", strMongo);
				bson_free (strMongo);
				regfree(&reg);
				bson_destroy (query);
				mongoc_cursor_destroy (cursor);
	    		}
			mongoc_collection_destroy (collection);
			mongoc_client_destroy (client);
			mongoc_cleanup ();  		
			break;
		}	
	}

	//-----Postlude
	Tspi_Context_Close(hContext);
	Tspi_Context_FreeMemory(hContext, NULL);
	// this frees memory that was automatically allocated for you
	Tspi_Context_Close(hContext);
	//-----------	
	if(shmdt(shm) == -1)	//delete shared memory from current process
    	{  
        	fprintf(stderr, "shmdt failed\n");  
        	exit(EXIT_FAILURE);  
    	} 
	return 0;
}
