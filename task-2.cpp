/**
 * Program:
 *	task-2.cpp
 * Author:
 *	brant-ruan
 * Date:
 *	2016-08-30
 * Function:
 *  Task 2 for Cryptography mission
 * Idea:
 *  ElGamal Algorithm
 * 
**/

#include <iostream>
#include <cstdio>
#include <iomanip>
#include <stdlib.h>
#include <NTL/ZZ.h> // NTL library 
#include <openssl/md5.h> // use libcrypto
#include <time.h>
#include <vector> // to store factors
#define PRIME_LENGTH 1024
#define ERROR -1
#define OK 0
#define GAMMA 0 // used in ElGamal signature
#define DELTA 1 // used in ElGamal signature
#define INTEGER 1024
#define YES 1
#define NO 0
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

/* add a factor to the vector */
int Add_Factor(ZZ x, vector<ZZ> &factors)
{
    vector<ZZ>::iterator it;
    for(it = factors.begin(); it != factors.end(); it++){
        if(*it == x)
            return OK;
    }
    factors.push_back(x);

    return OK;
}

/* to get factors of r */
int Gen_Factor(ZZ r, vector<ZZ> &factors)
{
    if(ProbPrime(r)) // r is prime, then add it
        Add_Factor(r, factors);
    else{
        long p;
        PrimeSeq s;
        p = s.next();
        ZZ tmp;
        while(1){
            if(ProbPrime(r)){ // r is prime, then add it
                Add_Factor(r, factors);
                break;
            }
            else if(r == 1 || r == 0) // end of parse
                break;
            if(r % p == 0){ // p is prime of r, add p
                tmp = p;
                Add_Factor(tmp, factors);
                r = r / p;
                s.reset(2);
                p = s.next();
            }
            else{ // p is not prime of r, continue
                p = s.next();
            }
        }
    }
    return OK;
}

/* signature generation */
int ElGamal_sign(ZZ md5_zz, ZZ &p, ZZ &alpha, ZZ &beta, ZZ &a, ZZ *sig)
{
    ZZ q0;
    cout << "get p..." << endl;
    // get p
    ZZ r; // p = r*q0 + 1
    srand(time(0));
    r = rand() % INTEGER;
    while(1){
        GenPrime(q0, PRIME_LENGTH);
        p = r * q0 + 1;
        if(ProbPrime(p)) // p is prime then break
            break;
    }
    cout << "r: " << r << endl;
    cout << "get a..." << endl;
    // get a
    ZZ pp;
    pp = p - 1;
    RandomBnd(a, pp); // Should I set a seed?
    cout << "get alpha..." << endl;
    // get alpha
    vector<ZZ> factors;
    Gen_Factor(r, factors); // parse the factors of p-1
    factors.push_back(q0); // p-1 = q0 * r, so add q0
    int flag;
    vector<ZZ>::iterator it;
    while(1){
        flag = YES;
        RandomBnd(alpha, pp);
        for(it = factors.begin(); it != factors.end(); it++){
            if(PowerMod(alpha, pp/(*it), p) == 1){
                flag = NO;
                break;
            }
        }
        if(flag == YES)
            break;
    } 

    for(it = factors.begin(); it != factors.end(); it++){
        cout << "factors: " << *it << endl;
    }
    cout << "get beta..." << endl;
    // get beta
    beta = PowerMod(alpha, a, p);
    // get signature
    ZZ k, k_inv; // k is a secret random number;
                // k_inv is its inverse element mod p-1
    while(1){
        RandomBnd(k, pp);
        if(GCD(k, pp) == 1)
            break;
    }
    sig[GAMMA] = PowerMod(alpha, k, p);
    
    ZZ temp, gcd, t;
    XGCD(gcd, k_inv, t, k, pp);
    while(k_inv < 0){
        k_inv += pp;
        k_inv %= pp;
    }
    temp = (md5_zz - a * sig[GAMMA]) % pp;
    sig[DELTA] = (temp * k_inv) % pp;
    while(sig[DELTA] < 0){
        sig[DELTA] += pp;
        sig[DELTA] %= pp;
    }

    cout << "----------------------------------------" << endl;
    cout << "Original file's MD5_ZZ: " << endl;
    cout << md5_zz << endl;
    cout << "----------------------------------------" << endl;
    cout << "Public key:" << endl;
    cout << "p: " << p << endl;
    cout << "alpha: " << alpha << endl;
    cout << "beta: " << beta << endl;
    cout << "----------------------------------------" << endl;
    cout << "Private key:" << endl;
    cout << "a: " << a << endl;
    cout << "----------------------------------------" << endl;
    cout << "Signature :" << endl;
    cout << "gamma: " << sig[GAMMA] << endl;
    cout << "delta: " << sig[DELTA] << endl;
    return OK;
}

int ElGamal_verify(ZZ md5_ver_zz, ZZ p, ZZ alpha, ZZ beta, ZZ *sig)
{

    cout << "----------------------------------------" << endl;
    ZZ bggd; // bggd is (Beta^Gamma)*(Gamma^Delta) mod p
    ZZ axp; // (Alpha^MD5) mod p
    bggd = (PowerMod(beta, sig[GAMMA], p) * PowerMod(sig[GAMMA], sig[DELTA], p)) % p; 
    axp = PowerMod(alpha, md5_ver_zz, p);

    cout << "Now file's MD5_ZZ: " << endl;
    cout << md5_ver_zz << endl;
    cout << "((Beta^Gamma)*(Gamma^Delta)) mod p:" << endl;
    cout << bggd << endl;
    cout << "(Alpha^MD5) mod p:" << endl;
    cout << axp << endl;

    cout << endl << endl;
    if(axp == bggd){
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
   
    ZZ p, alpha, beta, a, sig[2]; // ElGamal relative
    ElGamal_sign(md5_zz, p, alpha, beta, a, sig);

    cout << endl << endl;

// Verify the sign
    unsigned char md5_ver[17] = {0};

    cout << "Verify the signature for [" << argv[1] << "]..." << endl;
     
    if(MD5_gen(md5_ver, argv[1]) == ERROR){
        return ERROR;
    }

    ZZ md5_ver_zz;
    MD5_ZZ(md5_ver, md5_ver_zz);

    ElGamal_verify(md5_ver_zz, p, alpha, beta, sig);

	return 0;
}
