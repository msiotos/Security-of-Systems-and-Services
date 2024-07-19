#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/fsuid.h>
#include <openssl/md5.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

size_t loggingStats(int uid, const char* path, char* datetime, int access_type, int action_denied, FILE* log_file, unsigned char* md ) {
      
      char* fingerprint = "Fingerprint: ";
      char* new_line = "\n";
      char resolved_path[PATH_MAX];
      //To take the full path of the File
      if (realpath(path, resolved_path) == NULL) {
            perror("realpath");
            return EXIT_FAILURE;
      }

      fprintf(log_file, "User ID: %d\n", uid);
      fprintf(log_file, "File path: %s\n", resolved_path);
      fprintf(log_file, "Date and Time: %s", datetime);
      fprintf(log_file, "Access Type: %d\n", access_type);
      fprintf(log_file, "Action-denied Flag: %d\n", action_denied);

      if(md!=NULL) {
      fprintf(log_file,"%s", fingerprint);      
	for(int i = 0 ; i < sizeof(md);i++){
	fprintf(log_file,"%x", md[i]);
	}
	} else {
	fprintf(log_file,NULL);
	}
	fprintf(log_file,"%s",new_line);

}

FILE* fopen( const char* path, const char* mode) {

      //We want to see if the File exists
      int accessing = access(path, F_OK);

      //printf("Accessing is %d\n", accessing);
      printf("In our fopen, opening %s\n", path);

      FILE* (*original_fopen)(const char*, const char*);
      FILE* original_fopen_return;

      original_fopen = dlsym(RTLD_NEXT, "fopen");
      original_fopen_return = (*original_fopen)(path,mode);

      //Opening the Log file
      FILE* log_file = original_fopen("./file_logging.log", "a");
	if(log_file==NULL) {
		printf("Log file fopen failed.");
		return 0;
	}

      //Assigning Log details
      int uid;
      char* datetime;
      int access_type;
      int action_denied = 0;
      unsigned char* md = NULL;

      uid = getuid();
      __time_t t = time(NULL);
      datetime = ctime(&t);

      //If user doesnt have access to File
	if(errno == EACCES) { 
		action_denied = 1;
		access_type = 1;
		
		loggingStats(uid,path,datetime,access_type,action_denied,log_file,md);
	}

      //If File exists and user has access to File
      if(accessing != -1 && action_denied == 0) {
      long len;
      unsigned char* input_buffer = 0;

      FILE* temp = original_fopen(path,"r");
      if(temp != NULL) {
		fseek (temp, 0, SEEK_END);
  		len = ftell (temp);
  		fseek (temp, 0, SEEK_SET);

		input_buffer = malloc (len);
  		if (input_buffer) {
    		fread (input_buffer, 1, len, temp);
  		}
  		fclose (temp);

            //Here we find the Fingerprint
		md = MD5(input_buffer,len,md); 

		}
		
		access_type = 1;
		loggingStats(uid,path,datetime,access_type,action_denied,log_file,md);

      } else {

      //If File doesn't exist but get created
	if(errno==ENOENT && (strcmp(mode,"w") == 0 || strcmp(mode,"wb") == 0 || strcmp(mode,"a") == 0 || strcmp(mode,"ab") == 0) ) { 
		//file creation
		access_type = 0;
            
            //Code for initial fingerprint generation
            unsigned char fingerprint[MD5_DIGEST_LENGTH];
            calculate_fingerprint(path, fingerprint);
            printf("File didn't exist and gets created.\n");
            loggingStats(uid,path,datetime,access_type,action_denied,log_file,fingerprint);
	}
	}

	fclose(log_file);

	return original_fopen_return;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {

//printf("1st Check! it calls fwrite\n");

       FILE* original_fwrite_return; 
       FILE* (*original_fwrite)(const void*, size_t, size_t, FILE*);

       FILE* (*original_fopen)(const char*, const char*);
       original_fopen = dlsym(RTLD_NEXT, "fopen");
       
       original_fwrite = dlsym(RTLD_NEXT, "fwrite");
       original_fwrite_return = (*original_fwrite)(ptr, size, nmemb, stream);

//printf("2st Check! it come before the log file opening\n");

       //Opening the Log file
       FILE* log_file = original_fopen("./file_logging.log", "a");
       
 	 if(log_file==NULL) {
 		printf("Log file fopen failed.");
		return 0;
 	 }       

       //Assigning Log details
       int uid = getuid();
       char* datetime;
       int access_type = 2;
       int action_denied = 0;
      
       __time_t t = time(NULL);
       datetime = ctime(&t);

//printf("3st Check! it comes after the Log assignements\n");

 	char tmp[255];
       char filepath[255];

 	unsigned char md[MD5_DIGEST_LENGTH];
       MD5(ptr, nmemb, md); //fingerprint
      
       int fd = fileno(stream); 

 	sprintf(tmp, "/proc/self/fd/%d", fd);
      memset(filepath, 0, sizeof(filepath));
      readlink(tmp, filepath, sizeof(filepath)-1);

//printf("4st Check! it comes after the memset\n");

       const char s[2] = "/";
       char *token,*last_path;
       token = strtok(filepath, s);

       while( token != NULL ) {
 	last_path = token;
    
       token = strtok(NULL, s);
       }
//printf("5st Check! it come for the logging of everything\n");

 	loggingStats(uid,last_path,datetime,access_type,action_denied,log_file, md);
	
 	fclose(log_file); 

      return original_fwrite_return;

}

//THIS FUNCTION IS FOR GENERATING INITIAL FINGERPRINT UPON FILE CREATION
void calculate_fingerprint(const char *filename, unsigned char *fingerprint) {

    MD5_CTX md5;
    MD5_Init(&md5);

    // Include the file name in the hash
    MD5_Update(&md5, (unsigned char *)filename, strlen(filename));

    MD5_Final(fingerprint, &md5);
}

