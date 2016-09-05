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
#include <string.h>
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
int MD5_Gen(unsigned char *md5, const char *name)
{
    MD5_CTX c;  

    int len;  
    unsigned char *pData = (unsigned char *)name;
    
    MD5_Init(&c);  
    len = strlen(name);
    MD5_Update(&c, pData, len);  

    MD5_Final(md5,&c);  

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

int ElGamal_Print(ZZ &p, ZZ &alpha, ZZ &beta, ZZ &a)
{
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

int main(int argc, char **argv)
{
    cout << "Protocol 9.6 Test..." << endl;
    cout << "----------------------" << endl;
    cout << "P.S. We ignore the generation of certificate" << endl;
    cout << "     TA uses RSA Algorithm to sign; ElGamal for others" << endl;
    cout << "     ID(Alice) = \"Alice\"  ID(Bob) = \"Bob\"" << endl;
    cout << "----------------------" << endl;
// Firstly, TA generates certificates for Bob and Alice
// TA uses RSA, while it generates ElGamal certificates for Bog, Alice.
    unsigned char md5_a[17] = {0};
    unsigned char md5_b[17] = {0};
    ZZ md5_a_zz, md5_b_zz;
    cout << "Alice's pub/pri key:" << endl;
    if(MD5_Gen(md5_a, "Alice") == ERROR){
        return ERROR;
    }
    MD5_ZZ(md5_a, md5_a_zz);
    ZZ p_a, alpha_a, beta_a, a_a;
    conv(p_a,
    "80757801739461444376375076117462438809231992938697728838861479046791746617865323647383285380969791583219601608743347485950390997675587344904650053251515604847895215756531804158228157502253494743918892374020889447425704775531845939069208962536448065661067274098858478944632870211831619434912844780834664335755929");
    conv(alpha_a,
    "47137054963367559060867808541127380795787353211537798330395301468634140947325148127250148172700854104434242673380631251038701647715559391807880424797675968348340457111731851219367658154794026855851438197290501111886594351414419618574525000819034271815290897573205805883206166595197791470439534818319012247816039");
    conv(beta_a,
    "75822460250027107914970116964181032004032344913798526018466030476443076960645854945246614301999821624475093854139044562354511946449279530015779410907969117956611590197327176647673356360595267208510485635550907320366199006965502635349640240932093557059293334624945211092126365366900007146131550512885124202010035");
    conv(a_a,
    "27602905112968643282747339399639880715169485677889407537672951526759298478254380985929613867058219003994184483951205543503885568664928685280085504577860108676312629727377009121707748080089177179759885747060269987509167579951095433156852282654549286485854427570682619318924250733362814845872803130466928008425090");
    ElGamal_Print(p_a, alpha_a, beta_a, a_a);
    cout << endl;
    cout << "Bob's pub/pri key:" << endl;
    if(MD5_Gen(md5_b, "Bob") == ERROR){
        return ERROR;
    }
    MD5_ZZ(md5_b, md5_b_zz);
    ZZ p_b, alpha_b, beta_b, a_b;
    conv(p_b,
    "149432269103858053684213815122297781864722087914301874779908471945247575519160246670697422640821388062363614751439585101753945935759890896822599773208491274093634851328631726722911221097332153458220166209113798551213377095535346102011167673144507286073140681080686484878954544603707314706764556627376466256685211");
    conv(alpha_b,
    "65999146220466345754488507619029722842511672010868706346622270489535061521021956508230871951335209047658576385390371438507244398983605013565085675530803976611116428702193697761375722470807596032839944303583343362550344408731939573604930779417522162489573992587022738018666781505620558786413875025863942706587119");
    conv(beta_b,
    "100815518475849632077982767420043386633704412471980202189594428003992052701604881052848689454488375697557068358983913686247490079072890919324407116914495176325001443631730080814747136226936769948990936677944343070827669799872157690931694223378083498300541101789872382845247744770716622104812367670181554740057683");
    conv(a_b,
    "111858037259932300115162723522660548405633968033154311868386905422919187524302444793849711574401910698163970589920152244618812295527842251288507865840952943066435264472514293721643919429336602340758614250885602147338408060954915836329704399136489962079626739777215026550934561020497485124322227505481296858502184");
    ElGamal_Print(p_b, alpha_b, beta_b, a_b);
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
