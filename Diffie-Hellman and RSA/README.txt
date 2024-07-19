Assignment 1 - msiotos 2016030030 - gangelopoulos 2016030083

DIFFIE - HELLMAN KEY EXCHANGE

Here are the functions for dh_assign_1.c

main(int argc, char *argv[]) : The main function consists of the getopts function, responsible for taking the arguments from the terminal for the switch-case. atoi(optarg) takes the argument after the case option and converts it to integer. Its important to note that if p is not a prime number(we check it here) the program terminates with error message. If a or b are not between 1 and p-1 , then the program also terminates with error message. After the switch case , we open the output file, redirect the program output to it and we call the DH_Key_Ex function.

DH_Key_EX(int p, int g, int a,int b) : The primary function for the DH algorithm. First we calculate A, B using the modfunc below. Then we compute with the same function Alic'es and Bob's shared secret respectively. If they match, the algorithm is a success and we print the output to the output.txt file (as seen in main function), else we print an error message.

modfunc(int x, int y, int p) : We implemented this function to calculate x^y % p. First, we ensure that x is within the range of 0 to p-1 by reducing it to its modulo p value. Then using a while loop we perform modular exponentiation. The conditional check: if (y % 2 == 1), is used to check if y is odd, or else if the least significant bit of y is 1. If so, we update result by multiplying it by x and then taking the result modulo p. Then we perform integer division by 2 (or else bitwise right shift), we square x and reduce the result modulo p. Until y becomes 0, the last steps are repeated and when the loop exits the function returns the final result, which is x^y % p.

checkIfPrime (int num) :  This function checks if the argument is a prime number or not. First we initiate an integer i and a flag to 0. If the number is 0 or 1 or divisible by i then we assign flag = 1. If the returned flag is 1 then its not a prime number, if its 0 it is.

RSA ALGORITHM

Here are the functions for rsa_assign_1

main(int argc, char *argv[]) : The main function is the entry point for our RSA algorithm. It parses command-line arguments using the getopt function and then dispatches various tasks based on the provided options.  The format string "i:o:k:g:deah" specifies the expected options. Each case in the switch statement handles a specific option. After processing the options, we free the dynamically allocated memory for input_file, output_file, and key_file.

do_generation(int key_length) : This function generates RSA key pairs. Firstly we initialize the mpz_t variables. Then we generate the prime number p and the prime number q with lengths of keylength/2 by calling the generate_prime_number function. Then we calculate n as the product of p and q by using the mpz_mul and then we calculate lamda(n) as (p-1)*(q-1) by using mpz_mul after we've already substracted p and q by 1. Then we choose a prime number e by entering a loop again using the generate_prime_number function. We check that (e % lambda(n) != 0) and (gcd(e, lambda) == 1), using mpz_mod_ui and mpz_gcd. It continues generating until a valid e is found. After this, we calculate d, as the modular inverse of e modulo lambda(n) using the mod_inverse function. Lastly, we save the keys to files, the public key(n,e) to the public_length.key file and the private key(n,d) to the private_lenth.key file. We use gmp_fprintf to format and write the key components to the files and finally we clean up the resources by clearing the mpz_t variables to free the allocated memory.

The do_encryption and do_decryption are almost identical, we need the input,key and output files ( For the sake of testing we omitted the key file and we used our variables, see the Notes). We read from the input file the message with a while loop and getc. UNtil the end of file we take every stream and we encrypt it and store it in the output file.
The do_decryption is the same as do_encryption but a key difference is the function that decrypts before the end of the File.

void print_help_window() : Its a series of printfs, printing the menu.

void generate_prime_number(mpz_t rand_num, int length) : This function is for generating a prime number for the do_generation. Firstly, we initiate the rand_state and the rand_num variables for the GMP library to take effect. The mpz_urandomb is the one who generates a random number of a specific length and with mpz_setbit we check if it's the correct length. Secondly, we make sure that the number is an odd number and we increment it by 2 until we find a prime number. ALl this is implemented using GMP library functions.

int mod_inverse(mpz_t result, mpz_t num1, mpz_t num2) : This function uses one of the gmp library functions to calculate the inverse modulus of the arguments. It returns -1 if it doesnt exist and 0 if it does.

NOTES AND PROBLEMS TO CONSIDER

Do_generation does not work properly , because when it comes to compute the "e", the terminal is throwing "segmentation fault(core dumped) which is usually a problem in endless loops where resources are exhausted. The part where we write in the key files and the generation of p,q,n,lambda works fine but not all the key generation.
-As a result, we need to manually insert integers for e, n and d in the do_encryption and do_decryption so that we can test if those two run properly.
