#ifndef _SYMMETRY_H_
#define _SYMMETRY_H_


#include <cstdlib>

#include <iostream>
using std::cin;
using std::cout;
using std::endl;

#include <fstream>
using std::ifstream;
using std::ofstream;
using std::istreambuf_iterator;

#include <sstream>
using std::istringstream;
using std::ostringstream;

#include <string>
using std::string;
using std::getline;

#include <vector>
using std::vector;

#include <osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformation;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include <des.h>
using CryptoPP::DES_EDE2;

#include <aes.h>
using CryptoPP::AES;

#include <modes.h>
using CryptoPP::CBC_Mode;
using CryptoPP::OFB_Mode;

#include <sha.h>
using CryptoPP::SHA256;

#include <rsa.h>
using CryptoPP::RSA;
using CryptoPP::CryptoMaterial;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include <dsa.h>
using CryptoPP::DSA;

#include <queue.h>
using CryptoPP::ByteQueue;

#include <files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;


void AssignMasterPairs();
extern AutoSeededRandomPool prng;

#define EMAIL 0
#define FNAME 1
#define DOFBI 2
#define TELEP 3
#define ADDRE 4
#define PAPHR 5
#define SALTY 6
#define PRIKE 7
#define PUBKE 8
#define FIELD 9

#define KEYMK 0
#define SIGUP 1
#define ACCUP 2
#define ACCEX 3
#define KEYIM 4
#define DOCEN 5
#define DOCDE 6
#define SIGMK 7
#define SIGCK 8

#define KELEN 32
string Encrypt(const string& plain, byte* key, byte* iv, bool aes = true);
string Decrypt(const string& cipher, byte* key, byte* iv, bool aes = true);

#define DELIM "#####"
#define DATAL "database"
#define MAPAS "NguyePhanManhHungNguyeDinhAnVinh"
extern string MAIVE;

extern string MAPUB;
extern string MAPRI;

bool SaveDatabase();
vector<string> CurrentInDatabase();
bool AddToDatabase(const string& record);
vector<string> SearchDatabase(const string& key, int col = 0, int ret = -1);

bool LoadKey(const string& str, CryptoMaterial& key);
string SaveKey(const CryptoMaterial& key);

#define RSAKE 1024
#define PRIKL "private"
#define PUBKL "public"

bool SaveRandomPairs();
bool SignUp(const string& path);
string LogIn(const string& path);
bool Update(const string& path);




#endif