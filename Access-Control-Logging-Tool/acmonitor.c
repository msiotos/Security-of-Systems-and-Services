#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>

struct log_entry {

	int uid; 
	char *path; 
	char* datetime;
	int access_type; 
	int action_denied; 
	char *fingerprint; 

};

struct table {
	int uid;
	int modifications;
	};


void print_help_message(void)
{
	printf(
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void find_malicious_users(FILE *log_file) {

//printf("1st check(intro)\n");
	struct log_entry e = {0,NULL,NULL,0,0,NULL};

	size_t size = 0;
	ssize_t length = 0;
	char* line = NULL;
	int user_id;
	int action_denied = 0;
	char tmp1[10],tmp2[10],tmp3[20],tmp4[20];
	char  filepath[255];
	int users[1024],malicious[1024];
	int i ;
	int k = 0;
	int j = 0;
	int z = 0;
	int exists;
	struct log_entry en[100];  
//printf("2nd check(initialization)\n");

	for(int y = 0 ; y < 100; y++) {
		users[y] = -1;
		malicious[y] = -1;
	}
	
length = getline(&line,&size,log_file);
//printf("3rd check(length)\n");

while(length>=0) {

	if(strncmp(line,"User ID", 7)==0) {
		sscanf(line,"%s %s %d ", tmp1,tmp2,&user_id);
		//printf("4th check(user id)\n");

	}

	if(strncmp(line,"File path", 9)==0) {
		sscanf(line,"%s %s %s ", tmp3,tmp4,filepath);
		//printf("5th check(path)\n");

	}

	if(strncmp(line,"Action-denied Flag", 18)==0) {
		if(line[20] == '1') {
			action_denied = 1;
			en[k].uid = user_id;
//printf("6th check(action denied)\n");


			//fill users array with possible malicious users
			if(users[0] == -1) { //if array is empty
				users[0] = user_id;
				//printf("7th check(if array is empty\n");

			} else {

//printf("8th check(array not empty)\n");

				exists = 0;
				for(int y = 0; users[y] != -1; y++) { //check if user already exists in array
					if(users[y] == user_id) {
						exists = 1;
						//printf("9th check(user exists in array)\n");

					}
				}
				if(exists == 0) { //if user does not exist, add him
					z = 0;
					while(users[z]!=-1)
						z++;

					users[z] = user_id;
//printf("10th check(user doesnt exist-add him)\n");

				}
			}
			en[k].path = strdup(filepath);
			k++;	
			//printf("11th check(allocate memory)\n");

		}
	}

	length = getline(&line,&size,log_file);
	//printf("12th check(read next line)\n");

}

//check log_entry file for duplicates(same file accesed by same user)
for(int y = 0; y < k; y++) {
	for(int x = y+1; x < k; x++) {
		if( en[y].uid==en[x].uid && strcmp(en[y].path,en[x].path)==0) {
			en[x].uid = -1;
			//en[x].path = NULL;
				//printf("13th check(check dublicates (same file by same user))\n");
		}
	}
}


int index = 0;
//count malicious attempts
for(int y = 0; users[y]!=-1 ; y++) {
	int tresspasses = 0;
	for(int x = 0; x < k; x++){
		if((users[y]==en[x].uid) && (en[y].uid!=-1) ) {
			tresspasses++;
			if(tresspasses>=7) {
				malicious[index] = en[x].uid;
				index++;
				tresspasses = 0;
					//printf("14th check(malicious attempts)\n");
			}
		}
		
	}
}


//print malicious users
for(int l = 0; malicious[l]!=-1;l++){
	if( malicious[l+1] != malicious[i])
	printf("Malicious user %d with id %d\n",l,malicious[l]);
		//printf("15th check (print malicious users)\n");

}

free(line);
	//printf("16th check(reaches until the end)\n");

return;

}


void find_modifications(FILE *log_file, char *file_to_scan) {
	//printf("1st check(enters the function)\n");
	size_t size = 0;
	ssize_t length = 0;
	char* line = NULL;
	int user_id;
	char tmp1[10],tmp2[10],tmp3[10],tmp4[10],tmp5[10];
	char filepath[255],fingerprint[20];
	struct log_entry e = {0,NULL,NULL,0,0,NULL};
	struct table t = {0,0};
	struct log_entry en[1024];
	struct table tab[1024];
	int users[1024];
	int k = 0;
	int m = 0;
	int z = 0;
	int exists = 0;
	//printf("2nd check(initialization)\n");

	for(int y = 0 ; y < 100; y++) {
		users[y] = -1;
	}

	length = getline(&line,&size,log_file);
	//printf("3rd check(length)\n");

	while(length>=0) {

		if(strncmp(line,"User ID", 7)==0) {
		sscanf(line,"%s %s %d ", tmp1,tmp2,&user_id);
			//printf("4th check(user id)\n");

		}

		if(strncmp(line,"File path", 9)==0) {
		sscanf(line,"%s %s %s ", tmp3,tmp4,filepath);
			//printf("5th check(path)\n");

	}

	if(strncmp(line,"Fingerprint", 11)==0 && strcmp(filepath,file_to_scan)==0) {
		sscanf(line,"%s %s", tmp5,fingerprint);
			//printf("6th check(fingerprint)\n");

			if(users[0] == -1) { //if array is empty
				users[0] = user_id;
					//printf("7th check(array empty)\n");

			} else {

				exists = 0;
					//printf("8th check(array not empty)\n");

				for(int y = 0; users[y] != -1; y++) { //check if user already exists in array
					if(users[y] == user_id) {
						exists = 1;
							//printf("9th check(user exists in array)\n");
					}
				}

				if(exists == 0) { //if user does not exist, add him
					z = 0;
					//printf("10th check(user doesn't exist)\n");

					while(users[z]!=-1)
						z++;

					users[z] = user_id;
						//printf("11th check(add user)\n");


				}
				
			}
		

		en[k].fingerprint = strdup(fingerprint);
		en[k].uid = user_id;
		en[k].path = strdup(filepath);
		k++;
		//printf("12th check(Store user and file info)\n");
	}

	length = getline(&line,&size,log_file);
	//printf("13th check(next line)\n");

	}


	for(int i = 0; i < k ; i++) {
		for(int j = i+1; j < k;j++) {
			if((en[i].fingerprint,en[j].fingerprint)==0){
				en[j].fingerprint = "Duplicate!";
				//printf("14th check(Dublicate)\n");
			}
		}
	}

	for(int i = 0; users[i] != -1; i++) {
		int modifications = 0;
		for(int j = 1; j < k; j++) {
			if((en[j].uid==users[i]) && strcmp(en[j].fingerprint,"Duplicate!")!=0) {
				tab[m].uid = users[i];
				tab[m].modifications++;
				//printf("15th check(count modifications)\n");
			}
		}
		m++;
	}

	for(int i = 0; i < m; i++) {
		if(tab[i].modifications != 0) {
		printf("User %d -> Modifications: %d\n",tab[i].uid,tab[i].modifications);
		//printf("16th check(Prints user and modifications)\n");
	}
	else{
		printf("There have been no modifications.\n");
	}
	}
		//printf("17th check(exits)\n");
	return;

}


int main(int argc, char *argv[]) {

	int option;
	FILE *log_file;

	if (argc < 2)
		print_help_message();

	log_file = fopen("./file_logging.log", "r");
	if (log_file == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((option = getopt(argc, argv, "hi:m")) != -1) {
		switch (option) {		
		case 'i':
			find_modifications(log_file, optarg);
			break;
		case 'm':
			find_malicious_users(log_file);
			break;
		default:
			print_help_message();
		}

	}

	fclose(log_file);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
