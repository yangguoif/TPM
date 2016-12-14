#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/shm.h>
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
#define BUFFERSIZE 2048

union semun  
{  
    int val;  
    struct semid_ds *buf;  
    unsigned short *arry;  
};  

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

void main(int argc, char **argv){
	//----------------Preamble, initializing TPM chip
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
	//-----------------initializing TPM ends

	//-----------------initializing MongoDB connection
	mongoc_client_t *client;
  	mongoc_database_t *database;
   	mongoc_collection_t *collection;
   	bson_t *command, reply, *insert;
   	bson_error_t error;
   	char *str;
   	bool retval;
   	mongoc_init ();	//initialize libmongoc's internals
	client = mongoc_client_new ("mongodb://localhost:27017");	//Create a new client instance
   	database = mongoc_client_get_database (client, "logHash");
   	collection = mongoc_client_get_collection (client, "logHash", "testHash");	//Get a handle on the database
	//-----------------initializing MongoDB ends

	//-----------------initializing shared memory for the communication between check code and this code
	void *shm = NULL;	//the first memory address in this code for shared memory
	int shmid;	//shared memory id
	bool *restartCheck = NULL;	//a ptr point to the boolean value stored in the shared memory
	shmid = shmget((key_t)1234, sizeof(restartCheck), 0666|IPC_CREAT);
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
	restartCheck = (bool*) shm;

	//-----------------initializing shared memory ends
	//---------------initialize semaphore
	int sem_id = semget((key_t)1235, 1, 0666 | IPC_CREAT); 
	if(!set_semvalue(sem_id))  
        {  
            printf(stderr, "Failed to initialize semaphore\n");  
            exit(EXIT_FAILURE);  
        }  
	//-----------------------------
	char *inputFilePath = "/home/yg115/Downloads";
	char outputFilePath[80];	//output file path for the content in buffer, the new
							//file will be created and the fileNum will be added at the back
	char outputFilePath1[80];
	int i;
	char jsonForDB[200];	//help to organize json format for storing hash value into DB
	BYTE buffer[BUFFERSIZE];	//buffer for the content read from streaming data and going to write into log file
	BYTE bufferHash[20];	//buffer for hash value of the content in BYTE buffer
	char hashForDB[20];	//help to convert *BYTE to *char
	int fileNum = 1;	//number flag for log file name, used for strcat()
	char stringNum[25];	//help to convert int to *char
	resetPCR(hContext, 23);	//reset PCR23 for a new loop of checking
	FILE *fp = fopen(inputFilePath, "rb");
	if(setvbuf(fp, buffer, _IOFBF, BUFFERSIZE) != 0)
		printf("failed to setup buffer for input file");
	else{
		while(feof != 1){
			memset(bufferHash, 0, BUFFERSIZE);
			fread(buffer, sizeof(buffer), 1, fp);
			sleep(2);
			memset(bufferHash, 0, 20);
			HashThis(hContext, &buffer, BUFFERSIZE, &bufferHash);
			BYTE bufferCopy[sizeof(buffer)];
			memcpy(bufferCopy,buffer,sizeof(buffer));			


			snprintf(stringNum, 25, "%d", fileNum);	//generate outputFilePath
			fileNum++;
			memset(outputFilePath, 0, sizeof(outputFilePath)/sizeof(char));
			strcat(outputFilePath, "/home/yg115/test/generatedFile/");
			strcat(outputFilePath, stringNum);
			FILE *fpo = fopen(outputFilePath, "wb");
			size_t ret = fwrite(buffer, sizeof(BYTE), sizeof(buffer), fpo);	//write content in buffer into file
			fflush(fpo);
			fclose(fpo);
			
			memset(outputFilePath1, 0, sizeof(outputFilePath1)/sizeof(char));
			strcat(outputFilePath1, "/home/yg115/test/generatedFileCopy/");
			strcat(outputFilePath1, stringNum);
			FILE *fpo1 = fopen(outputFilePath1, "wb");
			size_t ret1 = fwrite(bufferCopy, sizeof(BYTE), sizeof(bufferCopy), fpo1);	//write content in buffer into file
			fflush(fpo1);
			fclose(fpo1);

			if(!semaphore_p(sem_id))  
           			exit(EXIT_FAILURE);
			extendPCR(hContext, 23, bufferHash);	//extend PCR23 to update a new hash value
			BYTE pcrValue2[20];
			readPCR(hContext, 23, pcrValue2);		
			*restartCheck = true;	//set shared memory, restart check in the check process
			if(!semaphore_v(sem_id)) 
           			exit(EXIT_FAILURE);
			memset(hashForDB, 0, 20);	//preparing writing MongoDB
			printf("\n pcr23 value after extend: ");
			for(i=0 ; i<19;++i){	//copy the hash value the the *char for json, and print the hash value
				char jj[2];
				sprintf(jj, "%02x", *(pcrValue2+i));
				strcat(hashForDB, jj);					
				printf("%02x",*(pcrValue2+i));
			}
			printf("\n");
			memset(jsonForDB, 0, sizeof(jsonForDB)/sizeof(jsonForDB));	//organizing Json format to convert to
			strcat(jsonForDB, "{\"fileName\":\"");				//BSON for DB writing
			strcat(jsonForDB, outputFilePath);
			strcat(jsonForDB, "\", \"hashValue\":\"");
			strcat(jsonForDB, hashForDB);
			strcat(jsonForDB, "\"}");
			printf("Json: %s \n", jsonForDB);
			
			insert = bson_new_from_json((const uint8_t *)jsonForDB, -1, &error);	//initialize BSON
			if (!mongoc_collection_insert (collection, MONGOC_INSERT_NONE, insert, NULL, &error)) {
        			fprintf (stderr, "%s\n", error.message);
    			}
		}
	}
	bson_destroy (insert);
   	mongoc_collection_destroy (collection);	//destroy mongodb connection
    	mongoc_client_destroy (client);
    	mongoc_cleanup ();
	fclose(inputFilePath);	//close file (data resource, should be TCP connection)  
   	if(shmdt(shm) == -1)	//delete shared memory from current process
    	{  
        	fprintf(stderr, "shmdt failed\n");  
        	exit(EXIT_FAILURE);  
    	} 
    	if(shmctl(shmid, IPC_RMID, 0) == -1)	//delete shared memory
    	{  
        	fprintf(stderr, "shmctl(IPC_RMID) failed\n");  
        	exit(EXIT_FAILURE);  
    	}  
	del_semvalue(sem_id);	//delete semaphore
	
}
