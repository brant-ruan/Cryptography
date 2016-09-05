/**
 * Program:
 *	task-4.cpp
 * Author:
 *	brant-ruan
 * Date:
 *	2016-09-03
 * Function:
 *  Task 4 for Cryptography mission
 * Idea:
 *  Use ElGamal 
 * P.S.
 *  Ignore real network communications
**/

#include <iostream>
#include <cstdio>
#include <iomanip>
#include <stdlib.h>
#include <NTL/ZZ.h> // NTL library 
#include <openssl/md5.h> // use libcrypto
#include <time.h>
#include <vector> // to store factors
#define ELGAMAL_PRIME_LENGTH 1024
#define RSA_PRIME_LENGTH 512
#define RANDOM_LENGTH 512
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
int MD5_Gen(unsigned char *md5, char *filename)
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

/* ElGamal signature function */
int ElGamal_Sign(ZZ md5_zz, ZZ &p, ZZ &alpha, ZZ &a, ZZ *sig)
{
    ZZ pp;
    pp = p - 1;
    // get signature
    ZZ k, k_inv; // k is a secret random number;
                // k_inv is its inverse element mod p-1
    RandomBnd(k, pp);
    sig[GAMMA] = PowerMod(alpha, k, p);
    
    ZZ temp, gcd, t;
    XGCD(gcd, k_inv, t, k, pp);
    while(k_inv < 0){
        k_inv += pp;
        k_inv %= pp;
    }
    temp = (md5_zz - a * sig[GAMMA]) % pp;
    sig[DELTA] = (temp * k_inv) % pp;
    return OK;
}

/* signature generation */
int ElGamal_Gen(ZZ &p, ZZ &alpha, ZZ &beta, ZZ &a)
{
    ZZ q0;
    // get p
    ZZ r; // p = r*q0 + 1
    srand(time(0));
    r = rand() % INTEGER;
    while(1){
        GenPrime(q0, ELGAMAL_PRIME_LENGTH);
        p = r * q0 + 1;
        if(ProbPrime(p)) // p is prime then break
            break;
    }
    // get a
    ZZ pp;
    pp = p - 1;
    RandomBnd(a, pp); // Should I set a seed?
    // get alpha
    vector<ZZ> factors;
    Gen_Factor(r, factors); // parse the factors of p-1
    factors.push_back(q0); // p-1 = q0 * r, so add q0
    int flag;
    while(1){
        flag = YES;
        RandomBnd(alpha, p);
        vector<ZZ>::iterator it;
        for(it = factors.begin(); it != factors.end(); it++){
            if(PowerMod(alpha, pp/(*it), p) == 1){
                flag = NO;
                break;
            }
        }
        if(flag == YES)
            break;
    } 

    // get beta
    beta = PowerMod(alpha, a, p);

    cout << "----------------------------------------" << endl;
    cout << "ElGamal Public key:" << endl;
    cout << "p: " << p << endl;
    cout << "alpha: " << alpha << endl;
    cout << "beta: " << beta << endl;
    cout << "----------------------------------------" << endl;
    cout << "ElGamal Private key:" << endl;
    cout << "a: " << a << endl;
    cout << "----------------------------------------" << endl;
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
        cout << "ElGamal Succeed." << endl;
        return YES;
    }
    else{
        cout << "ElGamal Fail." << endl;
        return NO;
    }
}

/* TA use RSA signature */
int RSA_sign(ZZ md5_zz, ZZ &p, ZZ &q, ZZ &n, ZZ &a, ZZ &b, ZZ &sig)
{
    GenPrime(p, RSA_PRIME_LENGTH);
    GenPrime(q, RSA_PRIME_LENGTH);
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
    cout << "TA's Public key:" << endl;
    cout << "n: " << n << endl;
    cout << "b: " << b << endl;
    cout << "----------------------------------------" << endl;
    cout << "TA's Private key:" << endl;
    cout << "p: " << p << endl;
    cout << "q: " << q << endl;
    cout << "a: " << a << endl;
    cout << "----------------------------------------" << endl;
    return OK;
}
/* TA'sRSA's verification*/
int RSA_verify(ZZ md5_ver_zz, ZZ sig, ZZ n, ZZ b)
{

    cout << "----------------------------------------" << endl;
    ZZ res = PowerMod(sig, b, n);
    cout << "RSA Origin(k):" << endl;
    cout << md5_ver_zz << endl;
    cout << "RSA Ver(k):" << endl;
    cout << res << endl;

    cout << endl << endl;
    if(md5_ver_zz == res){
        cout << "RSA Succeed." << endl;
        return YES;
    }
    else{
        cout << "RSA Fail." << endl;
        return NO;
    }
}

/* Print the usage */
void Usage(char *filename)
{
    cout << "Usage:" << endl;
    cout << "\t" << filename << " Alice-FILENAME Bob-FILENAME" << endl;
}

int main(int argc, char **argv)
{
    if(argc != 3){
        Usage(argv[0]);
        return 0;
    }
    
    cout << "Protocol 9.6 Test..." << endl;
    cout << "----------------------" << endl;
    cout << "P.S. We ignore the generation of certificate" << endl;
    cout << "     TA uses RSA Algorithm to sign; ElGamal for others" << endl;
    cout << "----------------------" << endl;
// Firstly, TA generates certificates for Bob and Alice
// TA uses RSA, while it generates ElGamal certificates for Bog, Alice.
    unsigned char md5_a[17] = {0};
    unsigned char md5_b[17] = {0};
    ZZ md5_a_zz, md5_b_zz;
    cout << "Generate Alice's pub/pri key..." << endl;
    if(MD5_Gen(md5_a, argv[1]) == ERROR){
        return ERROR;
    }
    MD5_ZZ(md5_a, md5_a_zz);
    ZZ p_a, alpha_a, beta_a, a_a;
    ElGamal_Gen(p_a, alpha_a, beta_a, a_a);
    cout << endl << endl;

    cout << "Generate Bob's pub/pri key..." << endl;
    if(MD5_Gen(md5_b, argv[2]) == ERROR){
        return ERROR;
    }
    MD5_ZZ(md5_b, md5_b_zz);
    ZZ p_b, alpha_b, beta_b, a_b;
    ElGamal_Gen(p_b, alpha_b, beta_b, a_b);
    cout << endl << endl;
    // TA signs for Bob and Alice to generate their certificates
    ZZ format_data_a, format_data_b;
    format_data_a = md5_a_zz + p_a % md5_a_zz + alpha_a % md5_a_zz
                    + beta_a % md5_a_zz;
    format_data_b = md5_b_zz + p_b % md5_b_zz + alpha_b % md5_b_zz
                    + beta_b % md5_b_zz;
    ZZ ta_a_p, ta_a_q, ta_a_n, ta_a_a, ta_a_b, ta_a_s;
    ZZ ta_b_p, ta_b_q, ta_b_n, ta_b_a, ta_b_b, ta_b_s;
    RSA_sign(format_data_a, ta_a_p, ta_a_q, ta_a_n, ta_a_a, ta_a_b, ta_a_s);
    RSA_sign(format_data_b, ta_b_p, ta_b_q, ta_b_n, ta_b_a, ta_b_b, ta_b_s);
///////////////////////////////////////////////////////////////////////////
    ZZ sig_a[2], sig_b[2]; // they represent y1, y2 in the book
    ZZ ElGamal_a, ElGamal_b; 
// Bob generates a random number r1
    ZZ r1;
    RandomBits(r1, RANDOM_LENGTH);
// Alice generates a random number r2
    ZZ r2;
    RandomBits(r2, RANDOM_LENGTH);
// Alice calculates y1 = sig(ID(Bob)||r1||r2)
    ElGamal_a = md5_b_zz + r1 % md5_b_zz + r2 % md5_b_zz;
    ElGamal_Sign(ElGamal_a, p_a, alpha_a, a_a, sig_a);
// Bob uses Alice's certificate to verify her pub-key,
    if(RSA_verify(format_data_a, ta_a_s, ta_a_n, ta_a_b) == NO){
        cout << "Alice's certificate is invalid. Exit." << endl;
        return ERROR;
    }
    else
        cout << "Alice's cetificate is valid." << endl;
// then uses her pub-key to verify y1; if true Bob accepts,
// else refuses.
    if(ElGamal_verify(ElGamal_a, p_a, alpha_a, beta_a, sig_a) == NO){
        cout << "Alice's signature is invald. Exit." << endl;
        return ERROR;
    }
    else
        cout << "Alice's signature is valid." << endl;

    cout << "Bob accepts Alice." << endl;
    cout << endl << endl;
// Bob calculates y2 = sig(ID(Alice)||r2)
    ElGamal_b = md5_a_zz + r2 % md5_a_zz;
    ElGamal_Sign(ElGamal_b, p_b, alpha_b, a_b, sig_b);
// Alice uses Bob's certificate to verify his pub-key,
    if(RSA_verify(format_data_b, ta_b_s, ta_b_n, ta_b_b) == NO){
        cout << "Bob's certificate is invalid. Exit." << endl;
        return ERROR;
    }
    else
        cout << "Bob's cetificate is valid." << endl;
// then uses his pub-key to verify y2; if true Alice accepts,
// else refuses.
    if(ElGamal_verify(ElGamal_b, p_b, alpha_b, beta_b, sig_b) == NO){
        cout << "Bob's signature is invald. Exit." << endl;
        return ERROR;
    }
    else
        cout << "Bob's signature is valid." << endl;
    
    cout << "Alice accepts Bob." << endl;
    cout << endl << endl;
    cout << "Identification Succeed." << endl; 
	return 0;
}
