#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <time.h> 
#include <gmp.h>

void do_generation(int length);
void do_decryption(char* input, char* output);
int do_encryption(char* input, char* output);
void do_comparison(void);
void print_help_window(void);
int checkIfPrime(mpz_t num);
void generate_prime_number(mpz_t rand_num, int length);
int mod_inverse(mpz_t result, mpz_t num1, mpz_t num2);
int mod_pow(int base, int exp, int mod);


int main(int argc, char *argv[]) {

int   opt;
char* input_file;
char* output_file;
char* key_file;

input_file = NULL;
output_file =  NULL;
key_file = NULL;

    // we use getopt to get the arguments from the terminal
    while ((opt = getopt(argc, argv, "i:o:k:g:dea:h")) != -1) {
    switch (opt) {
    case 'i':
        input_file = strdup(optarg);
        break;

    case 'o':
        output_file = strdup(optarg);
        break;

    case 'k':
        key_file = strdup(optarg);
        break;

    case 'g':
        if (optarg == NULL) {
            fprintf(stderr, "Missing key length argument for -g option.\n");
            return 1;
        }
        do_generation(atoi(optarg));
        break;

    case 'd':
        do_decryption(input_file, output_file);
        break;

    case 'e':
        do_encryption(input_file, output_file);
        break;

    case 'a':
        do_comparison();
        break;

    case 'h':
        print_help_window();
        break;
    default:
    }
}

// Free the files
free(input_file);
free(output_file);
free(key_file);

return 0;
}

// ************************* Implementation Functions ******************************************
// *********************************************************************************************

void do_generation(int key_length) {
    mpz_t p, q, n, lambda, e, d;

    mpz_inits(p, q, n, lambda, e, d, NULL);


    /// Generate p
    generate_prime_number(p, key_length / 2);

// Generate q
    do {
        generate_prime_number(q, key_length / 2);
    } while (mpz_cmp(p, q) == 0);

    // Calculate n
    mpz_mul(n, p, q);

    // Calculate lambda(n)
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(lambda, p, q);

    // Choose a prime e where (e % lambda(n) != 0) AND (gcd(e, lambda) == 1)
    int e_valid = 0;
    do {
        generate_prime_number(e, key_length / 2);
        int mod_result = mpz_mod_ui(NULL, e, mpz_get_ui(lambda));
        mpz_t gcd_result;
        mpz_init(gcd_result);
        mpz_gcd(gcd_result, e, lambda);
        e_valid = (mod_result != 0) && mpz_cmp_ui(gcd_result, 1) == 0;
        mpz_clear(gcd_result);
    } while (!e_valid);

    // Calculate d as the modular inverse of e modulo lambda(n)
    mod_inverse(d, e, lambda);

    char public_filename[] = "public.key";
    char private_filename[] = "private.key";

    // The public key is (n, e), and the private key is (n, d)
    FILE *public_file = fopen("public_length.key", "a");
    if (public_file == NULL) {
        perror("Failed to open public file");
        return;
    }

    // Redirect stdout to the file
    dup2(fileno(public_file), fileno(stdout));

    gmp_fprintf(public_file, "%Zd, %Zd\n", n, e);

    // Close the file
    fclose(public_file);

    FILE *private_file = fopen("private_length.key", "a");
    if (private_file == NULL) {
        perror("Failed to open private file");
        return;
    }

    // Redirect stdout to the file
    dup2(fileno(private_file), fileno(stdout));

    gmp_fprintf(private_file, "%Zd, %Zd\n", n, d);

    // Close the file
    fclose(private_file);

    // Don't forget to clean up resources:
    mpz_clears(p, q, n, lambda, e, d, NULL);
}



void do_decryption(char* input, char* output) {

    char message;
    mpz_t d, n;

   int value1 = 2753;
   int value2 = 3233;
   mpz_set_si(d, value1);
   mpz_set_si(n, value2);

    FILE *input_file = fopen(input, "r");
    if (input_file == NULL) {
        perror("Failed to open input file");
        return -1;
    }



    FILE *output_file = fopen(output, "w");
    if (output_file == NULL) {
        perror("Failed to open output file");
        return -1;
    }



    //Here we decrypt until we find the end of File
    
    fclose(input_file);
    fclose(output_file);

}

int do_encryption(char* input, char* output) {

    mpz_t n, e;
    mpz_inits(n, e, NULL);
    char message;
   int value1 = 17;
   int value2 = 3233;
   mpz_set_si(e, value1);
   mpz_set_si(n, value2);
    FILE *input_file = fopen(input, "r");
    if (input_file == NULL) {
        perror("Failed to open input file");
        return -1;
    }



    FILE *output_file = fopen(output, "w");
    if (output_file == NULL) {
        perror("Failed to open output file");
        return -1;
    }


    //Here we encrypt until we find the end of File
    while((message = fgetc(input_file)) != EOF) {    
    int encrypt = mod_pow(message, e, n);
    fwrite(&encrypt,8,1,output_file);
    }
    
    fclose(input_file);
    fclose(output_file);
    mpz_clears(n, e, NULL);
    return 0;

}

void do_comparison() {

}

void print_help_window() {
printf("Options:\n");
printf("-i path Path to the input file \n");
printf("-o path Path to the output file\n");
printf("-k path Path to the key file\n");
printf("-g length Perform RSA key-pair generation given a key length “length”\n");
printf("-d Decrypt input and store results to output.\n");
printf("-e Encrypt input and store results to output.\n");
printf("-a Compare the performance of RSA encryption and decryption with three different key lengths (1024, 2048, 4096 key lengths) in terms of computational time.\n");
printf("-h This help message \n");
printf("\n");
printf("The arguments “i”, “o” and “k” are always required when using “e” or “d” \n");
printf("Using -i and a path the user specifies the path to the input file. \n");
printf("Using -o and a path the user specifies the path to the output file. \n");
printf("Using -k and a path the user specifies the path to the key file. \n");
printf("Using -g the tool generates a public and a private key given a key length “length” and stores them to the public_length.key and private_length.key files respectively. \n");
printf("Using -d the user specifies that the tool should read the ciphertext from the input file, decrypt it and then store the plaintext in the output file. \n");
printf("Using -e the user specifies that the tool should read the plaintext from the input file, encrypt it and store the ciphertext in the output file. \n");
printf("Using -a the user generates three distinct sets of public and private key pairs, allowing for a comparison of the encryption and decryption times for each. \n");
}

// ***************************** Useful Functions **********************************************
// *********************************************************************************************

void generate_prime_number(mpz_t rand_num, int length) {
    gmp_randstate_t rand_state;
    
    mpz_init(rand_num);
    gmp_randinit_default(rand_state);
    gmp_randseed_ui(rand_state, time(NULL));  // Seed the random state with the current time
    
    do {
        mpz_urandomb(rand_num, rand_state, length);
        mpz_setbit(rand_num, length - 1);  // Set the most significant bit to 1 to ensure the number is of the desired length

        // Ensure that the generated number is odd
        if (mpz_even_p(rand_num)) {
            mpz_add_ui(rand_num, rand_num, 1);
        }
    } while (mpz_probab_prime_p(rand_num, 25) == 0); // Keep generating until a prime number is found

    gmp_randclear(rand_state);
}


int mod_inverse(mpz_t result, mpz_t num1, mpz_t num2) {
    if (mpz_invert(result, num1, num2) == 0) {
        return -1;  // Inverse does not exist
    }
    return 0;  // Inverse exists
}

int mod_pow(int base, int exp, int mod) {

    if (mod == 1)
        return 0;

    int c = 1;
    for (int i = 0; i <= exp-1; i++) { 
        c = (c * base) % mod;
    }
    return c;
}
