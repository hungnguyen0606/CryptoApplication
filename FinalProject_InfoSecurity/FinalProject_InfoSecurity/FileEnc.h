#ifndef _FILE_ENC_H_
#define _FILE_ENC_H_
#include "symmetry.h"
#include <string>
#include "dsa.h"
using CryptoPP::DSA;

std::string makeSignature(const string& path, string PrivateKey);
int verifySignature(const string& pathFile, const string& pathSign);
bool decryptFile(const string& src, const string& dest, const string& PrivateKey);
bool encryptFile(const string& src, const string& dest, bool isAES, const string& email);
#endif