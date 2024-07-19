#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/fsuid.h>
#include <sys/types.h>
#include <unistd.h> 
#include <stdlib.h>

int main() {

FILE *FD1, *FD2, *FD3, *FD4, *FD5, *FD6, *FD7, *FD8, *FD9;

//File Creation x9
FD1 = fopen("test1.txt", "w");
if(FD1 == NULL){
    printf("fopen failed!\n");
}

FD2 = fopen("test2.txt", "w");
if(FD2 == NULL){
    printf("fopen failed!\n");
}

FD3 = fopen("test3.txt", "w");
if(FD3 == NULL){
    printf("fopen failed!\n");
}

FD4 = fopen("test4.txt", "w");
if(FD4 == NULL){
    printf("fopen failed!\n");
}

FD5 = fopen("test5.txt", "w");
if(FD5 == NULL){
    printf("fopen failed!\n");
}

FD6 = fopen("test6.txt", "w");
if(FD6 == NULL){
    printf("fopen failed!\n");
}

FD7 = fopen("test7.txt", "w");
if(FD7 == NULL){
    printf("fopen failed!\n");
}

FD8 = fopen("test8.txt", "w");
if(FD8 == NULL){
    printf("fopen failed!\n");
}

FD9 = fopen("test9.txt", "w");
if(FD9 == NULL){
    printf("fopen failed!");
}
//File Existing and Opening Again x1

FD1 = fopen("test1.txt", "w");
if(FD1 == NULL){
    printf("fopen failed!\n");
}

//File Writing 
   char str1[] = "Hello File 1!";

   size_t bytes_written = fwrite(str1, 1, sizeof(str1) - 1, FD1);
   //printf("Fwrite success check!\n");
   if (bytes_written != strlen(str1)) {
       perror("fwrite failed");
       fclose(FD1);
       return 1;
   }

if(chmod("test2.txt" ,S_IRGRP ) < 0){ //change rights
        printf("Error with chmod");
        return 0;
    }
if(chmod("test3.txt" ,S_IRGRP ) < 0){ //change rights
        printf("Error with chmod");
        return 0;
    }
if(chmod("test4.txt" ,S_IRGRP ) < 0){ //change rights
        printf("Error with chmod");
        return 0;
    }
if(chmod("test5.txt" ,S_IRGRP ) < 0){ //change rights
        printf("Error with chmod");
        return 0;
    }
if(chmod("test6.txt" ,S_IRGRP ) < 0){ //change rights
        printf("Error with chmod");
        return 0;
    }
if(chmod("test7.txt" ,S_IRGRP ) < 0){ //change rights
        printf("Error with chmod");
        return 0;
    }
if(chmod("test8.txt" ,S_IRGRP ) < 0){ //change rights
        printf("Error with chmod");
        return 0;
    }
if(chmod("test9.txt" ,S_IRGRP ) < 0){ //change rights
        printf("Error with chmod");
        return 0;
    }


FD2 = fopen("test2.txt", "w");
    if(FD2 == NULL) {
    printf("fopen failed!\n");
    }

FD2 = fopen("test2.txt", "w");
    if(FD2 == NULL) {
    printf("fopen failed!\n"); //in order to check that dublicates don't count when checking for malicious users
    }

FD3 = fopen("test3.txt", "w");
    if(FD3 == NULL) {
    printf("fopen failed!\n");
    }   

FD4 = fopen("test4.txt", "w");
    if(FD4 == NULL) {
    printf("fopen failed!\n");
    }

FD5 = fopen("test5.txt", "w");
    if(FD5 == NULL) {
    printf("fopen failed!\n");
    }   
FD6 = fopen("test6.txt", "w");
    if(FD6 == NULL) {
    printf("fopen failed!\n");
    }

FD7 = fopen("test7.txt", "w");
    if(FD7 == NULL) {
    printf("fopen failed!\n");
    }   
FD8 = fopen("test8.txt", "w");
    if(FD8 == NULL) {
    printf("fopen failed!\n");
    }

FD9 = fopen("test9.txt", "w");
    if(FD9 == NULL) {
    printf("fopen failed!\n");
    }   


fclose(FD1);
fclose(FD2);
fclose(FD3);
fclose(FD4);
fclose(FD5);
fclose(FD6);
fclose(FD7);
fclose(FD8);
fclose(FD9);

return 0;

}