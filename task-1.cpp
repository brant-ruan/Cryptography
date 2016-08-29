/**
 * Program:
 *	task-1.cpp
 * Author:
 *	brant-ruan
 * Date:
 *	2016-08-25
 * Function:
 *  Task 1 for Cryptography mission
 * Idea:
 *  Use MD5 to hash a file and use RSA to sign the MD5 string.
 *  When getting the file&signature, hash and use RSA to verify it.
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
    cout << "Original file's MD5_ZZ: " << endl;
    cout << md5_zz << endl;
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
    cout << "Signature :" << endl;
    cout << sig << endl;
    return OK;
}

int RSA_verify(ZZ md5_ver_zz, ZZ sig, ZZ n, ZZ b)
{

    cout << "----------------------------------------" << endl;
    ZZ res = PowerMod(sig, b, n);
    cout << "Now file's MD5_ZZ: " << endl;
    cout << md5_ver_zz << endl;
    cout << "Ver(k): " << endl;
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
    cout << "Usage:\n" << "\t" << filename << " FILENAME" << endl;
}

int main(int argc, char **argv)
{
    if(argc != 2){
        Usage(argv[0]);
        return 0;
    }

// Generate the signature
    unsigned char md5[17]={0}; // file's md5 result

    cout << "Generate the signature for [" << argv[1] << "]..." << endl;

    if(MD5_gen(md5, argv[1]) == ERROR){
        return ERROR;
    }
    ZZ md5_zz;
    MD5_ZZ(md5, md5_zz);
   
    ZZ p, q, n, a, b, sig; // RSA relative
    RSA_sign(md5_zz, p, q, n, a, b, sig);

    cout << endl << endl;

// Verify the sign
    unsigned char md5_ver[17] = {0};

    cout << "Verify the signature for [" << argv[1] << "]..." << endl;
     
    if(MD5_gen(md5_ver, argv[1]) == ERROR){
        return ERROR;
    }

    ZZ md5_ver_zz;
    MD5_ZZ(md5_ver, md5_ver_zz);

    RSA_verify(md5_ver_zz, sig, n, b);

	return 0;
}
