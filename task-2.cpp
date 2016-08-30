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
 *  
 * 
**/

/**
My Program works correctly most of the time.However when I tested it one exception happened.
Maybe the reason is NTL's question or others. But I must record it:
----------------------------------------
Original file's MD5_ZZ: 
3644495476578496733443765829689
----------------------------------------
Public key:
p: 153237313780048104378630829064307316501801364166498408867568738038360205812123770232360232652011580793793087604669314603592753978108498281330904008822712121174693671369450975934339799315909437716677872396638218180059055172192332318846916545507678784107453676603481975118412448616498424059377323300029783532765029
alpha: 141863510751215965808737388237225071721595601091037554248365821141262497906650541544075806414082532204930190707433742361801279364405793219533609297907068619225830419148632998837004367866515559458285017039691340994022739917109664852077668633531103549569048088297209657001322675048672774363934484506797666125768643
beta: 47577576542265111855406185011707768572570864576579865861483462353486005339187610919648091791363683030406327720323535565514748350902926340521914905448749049591166562023676932806802840185538596555411942994881972551007454733718258861709265106004718443116578669508357674676500925888481360235192712306191844169967966
----------------------------------------
Private key:
a: 42146957334465601544695700036775266522517549322470631644112371041044095687777955519431135593061348198782271823904482061563919808991439861202584281619851265663010682312290849529769559115037350085389147795137198350650546769654729058659150221201325568742593037865880244847704257709640000461470245086333234244823130
----------------------------------------
Signature :
gamma: 48758952198391534157887180190687641476595203621505741130343568867860321203230354320098946459023997719411948875804697892074167044706668224308069330422935079174545224720673562476177106068085926971986822466319397668782258025317105634656363090236961840631324907886610819363337487127559417070929350356717424229481643
delta: 31684355689733685858762273777819572533334117170496088748719632130026476581413547613266141988500809768383295554632214952441238893612429786138738374738749080458393485066134313437391589982165545184634568912720074667777590395593841382750272990041195368129454505825714338419068924614254327971019217864330083002656499


Verify the signature for [others]...
----------------------------------------
Now file's MD5_ZZ: 
3644495476578496733443765829689
((Beta^Gamma)*(Gamma^Delta)) mod p:
131020031049982128320804102998175462631392194888245514490597555760935822137043401861148188661218058906769214481886406156172818557023887544183162187007094052574847836862566949048381201285122812055950368753531807455631441138453158317209940149409028675653854566849100463874700739581126970349550401114451326465447011
(Alpha^MD5) mod p:
36537689095681949852604380699116889764158531969648311221608364252873329868866556661696426532696302214021694678533383318366931462737931098209197072795375539239488380066768832119688236872650489082517122927489162035971621907396861582458637677933466894608534288808972196460425540021073152475124130136755140012854709


Fail.

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
    cout << "get beta..." << endl;
    // get beta
    beta = PowerMod(alpha, a, p);
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
