/**
 * Program:
 *	task-3.cpp
 * Author:
 *	brant-ruan
 * Date:
 *	2016-08-31
 * Function:
 *  Task 3 for Cryptography mission
 * Idea:
 *  Use RSA
 * 
**/

#include <iostream>
#include <cstdio>
#include <iomanip>
#include <stdlib.h>
#include <NTL/ZZ.h> // NTL library 
#include <openssl/md5.h> // use libcrypto
#include <time.h>
#define PRIME_LENGTH 512
#define ERROR -1
#define OK 0

using namespace std;
using namespace NTL; // use NTL namespace

/* MD5 */
int MD5_gen(unsigned char *md5, char *filename)
{
    FILE *fd=fopen(filename,"r");  
    MD5_CTX c;  
    if(fd == NULL)  
    {  
        cout << filename << " open failed" << endl;
        return ERROR;
    }  

    int len;  
    unsigned char *pData = (unsigned char*)malloc(1024*1024*1024);  

    if(!pData)  
    {  
        cout << "malloc failed" << endl;  
        return ERROR;  
    }  

    MD5_Init(&c);  

    while( 0 != (len = fread(pData, 1, 1024*1024*1024, fd) ) )  
    {  
        MD5_Update(&c, pData, len);  
    }  

    MD5_Final(md5,&c);  

    fclose(fd);  
    free(pData);  

    return OK;
}

/* MD5 value to ZZ number */
int MD5_ZZ(unsigned char *md5, ZZ &md5_zz)
{
    ZZ base_num;
    md5_zz = 0;
    base_num = 2;
    long bitnum = 32;

    for(int i = 0; i < 3; i++){
        md5_zz += (unsigned int)md5[i*4];
        md5_zz *= power(base_num, bitnum);
    }
    md5_zz += (unsigned int)md5[3*4];

    return OK; 
}

int RSA_sign(ZZ md5_zz, ZZ &p, ZZ &q, ZZ &n, ZZ &a, ZZ &b, ZZ &sig)
{
    GenPrime(p, PRIME_LENGTH);
    GenPrime(q, PRIME_LENGTH);
    n = p * q;
    ZZ euler, d, t;
    euler = (p-1) * (q-1); // Euler'so totient function
    while(1){ // to generate a
        srand(time(0));
        GenPrime(a, rand()%128);
        if(a < euler)
            break;
    }

    XGCD(d, b, t, a, euler);
    while(b < 0){
        b += euler;
        b %= euler;
    }

    sig = PowerMod(md5_zz, a, n);

    cout << "----------------------------------------" << endl;
    cout << "Public key:" << endl;
    cout << "n: " << n << endl;
    cout << "b: " << b << endl;
    cout << "----------------------------------------" << endl;
    cout << "Private key:" << endl;
    cout << "p: " << p << endl;
    cout << "q: " << q << endl;
    cout << "a: " << a << endl;
    cout << "----------------------------------------" << endl;
    return OK;
}

int RSA_verify(ZZ md5_ver_zz, ZZ sig, ZZ n, ZZ b)
{

    cout << "----------------------------------------" << endl;
    ZZ res = PowerMod(sig, b, n);
    cout << "Origin(k):" << endl;
    cout << md5_ver_zz << endl;
    cout << "Ver(k):" << endl;
    cout << res << endl;

    cout << endl << endl;
    if(md5_ver_zz == res){
        cout << "Succeed." << endl;
    }
    else{
        cout << "Fail." << endl;
    }

    return OK;
}

/* Print the usage */
void Usage(char *filename)
{
    cout << "Usage:\n" << "\t" << filename << " ALICE-FILENAME" << endl;
}

int main(int argc, char **argv)
{
    if(argc != 2){
        Usage(argv[0]);
        return 0;
    }
// Generate ID(Alice) -- MD5 (Require Ailice in a file)
    unsigned char md5[17] = {0};
    
    if(MD5_gen(md5, argv[1]) == ERROR){
        return ERROR;
    }
    ZZ md5_zz; // ID(Alice)
    MD5_ZZ(md5, md5_zz);
        
    cout << "Protocol 9.5 Test..." << endl << endl;

    cout << "TA generates Pri/Pub key for Alice" << endl;
// TA generates Pri/Pub key for Alice
    ZZ alice_p, alice_q, alice_n, alice_a, alice_b, alice_s; // alice_s is unuseful
    RSA_sign(md5_zz, alice_p, alice_q, alice_n, alice_a, alice_b, alice_s); // just want RSA key

    cout << endl << endl;

    cout << "TA signs for Alice" << endl;

// Generate TA's Pri/Pub key and signs for ID(Alice) + Alice's Pub key
    ZZ ta_p, ta_q, ta_n, ta_a, ta_b, ta_s; // ta_s is TA's signature for Alice
    // the data TA sign is (ID(Alice)||ver(Alice))
    // I use a formula to format it: MD5 + alice_n + alice_b
    ZZ format_data;
    format_data = md5_zz + alice_n % md5_zz + alice_b % md5_zz;
    // format_data = md5_zz;
    RSA_sign(format_data, ta_p, ta_q, ta_n, ta_a, ta_b, ta_s); // ta_s is signature
    cout << "Alice's Certificate:" << endl;
    cout << "ID(Alice) (MD5):" << endl;
    cout << md5_zz << endl;
    cout << "Alice's Public key:" << endl;
    cout << "n: " << alice_n << endl;
    cout << "b: " << alice_b << endl;
    cout << "TA's signature for Alice:" << endl;
    cout << ta_s << endl;
    cout << "----------------------------------------" << endl;

    cout << endl << endl;
// Certificate is (ID(Alice) + Alice's Pub key + signature)
    cout << "Now Alice has her certificate and private key." << endl;
    cout << "In a session, she sends her certificate to Bob." << endl;
    cout << "Bob now has TA's Verify-key and Alice's certificate." << endl;
    cout << "He verifies the certificate:" << endl;
    
// Bob verifies TA's signature
    ZZ bob_format_data;
    bob_format_data = md5_zz + alice_n % md5_zz + alice_b % md5_zz;
    // bob_format_data = md5_zz;
    
    RSA_verify(bob_format_data, ta_s, ta_n, ta_b);
    
    return 0;
}
