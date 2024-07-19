#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// Function to calculate (x^y) % p
int modfunc(int x, int y, int p) {
    int result = 1;
    x = x % p;
    while (y > 0) {
        if (y % 2 == 1)
            result = (result * x) % p;
        y = y / 2; // Right-shift y by 1 (equivalent to dividing by 2)
        x = (x * x) % p;
    }
    return result;
}

int main() {

    int p = 23; // Shared prime number p
    int g = 5; // Shared base g

    // Secret keys a and b
    int a, b;

    // a and b get random secret values between 1 and p-1
    a = rand() % (p - 1) + 1;
    b = rand() % (p - 1) + 1;

    // We calculate A and B using the function above
    int A = modfunc(g, a, p);
    int B = modfunc(g, b, p);

    // We assume that Alice and Bob exchange A and B values through a separate secure communication channel

    // Alice computes the shared secret
    int sAlice = modfunc(B, a, p);

     // Bob computes the shared secret
    int sBob = modfunc(A, b, p);

    // Find out if the secret is shared
    if (sAlice == sBob) {
        printf("The secret is shared\n");
    } else {
        printf("Error: Secret couldn't be shared\n");
    }

    return 0;
}
