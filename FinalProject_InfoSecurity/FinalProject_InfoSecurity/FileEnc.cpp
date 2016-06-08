#include "FileEnc.h"
#include <hex.h>
#include <pubkey.h>
#include <secblock.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <md5.h>
//#include <rsa.h>

using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::ArraySink;
using CryptoPP::RSASSA_PKCS1v15_SHA_Signer;
using CryptoPP::RSASSA_PKCS1v15_SHA_Verifier;
#define UNERR "Unknown exception."
#define NOOUTPUT "My exception: Cannot create output file."
#define NOINPUT "My exception: Cannot open source file."
#define NOLOADKEY "Cannot load the key."
std::string makeSignature(const string& path, string PrivateKey)
{
	try
	{
		RSA::PrivateKey privateKey;
		//call load key
		if (!LoadKey(PrivateKey, privateKey))
			throw string(NOLOADKEY);
	
		ifstream ifs(path, std::ios::binary);
		if (!ifs.good())
			throw string(NOINPUT);
		string message((istreambuf_iterator<char>(ifs)), (istreambuf_iterator<char>()));

		//sign message
		RSASSA_PKCS1v15_SHA_Signer signer(privateKey);
		size_t length = signer.MaxSignatureLength();
		CryptoPP::SecByteBlock signature(length);
		length = signer.SignMessage(prng, (const byte*)message.c_str(),
			message.length(), signature);
		signature.resize(length);

		return string(signature.begin(), signature.end());
	}
	catch (string e)
	{
		cout << e << endl;
		return "";
	}
	catch (const std::exception& e)
	{
		cout << e.what() << endl;
		return "";
	}
	catch (...)
	{
		cout << UNERR;
		return "";
	}
	
}



int verifySignature(const string& pathFile, const string& pathSign)
{
	try
	{
		ifstream ifsM(pathFile, std::ios::binary);
		if (!ifsM.good())
			throw string(NOINPUT);
		ifstream ifsS(pathSign, std::ios::binary);
		if (!ifsS.good())
		{
			ifsM.close();
			throw string(NOINPUT);
		}
			
		string message((istreambuf_iterator<char>(ifsM)), (istreambuf_iterator<char>()));
		string signature((istreambuf_iterator<char>(ifsS)),	(istreambuf_iterator<char>()));

		vector<string> data = SearchDatabase("", -1, PUBKE);
		for (int i = 0; i < data.size(); ++i)
		{

			RSA::PublicKey myKey;
			LoadKey(data[i], myKey);

			//verify message
			RSASSA_PKCS1v15_SHA_Verifier verifier(myKey);
			bool result = verifier.VerifyMessage((const byte*)message.c_str(),
				message.length(), (const byte*)signature.c_str(), signature.size());
			if (result)
			{
				vector<string> mail = SearchDatabase(data[i], PUBKE, EMAIL);
				cout << "This file has been signed by " + mail[0] << endl;
				return true;
			}
		}
		return false;
	}
	catch (string e)
	{
		cout << e << endl;
		return false;
	}
	catch (const std::exception& e)
	{
		cout << e.what() << endl;
		return false;
	}
	catch (...)
	{
		cout << UNERR;
		return false;
	}
	
}

bool encryptFile(const string& src, const string& dest, bool isAES, const string& email)
{
	try
	{
		vector<string> temp = SearchDatabase(email, 0, 8);

		if (temp.size() < 1)
			throw string("This email doesn't exist.");

		ifstream ifs(src, std::ios::binary);
		if (!ifs.good())
			throw string(NOINPUT);

		ofstream ofs(dest, std::ios::binary);
		if (!ofs.good())
		{
			if (ifs.is_open()) 
				ifs.close();
			throw string(NOOUTPUT);
		}
			

		string message((istreambuf_iterator<char>(ifs)),
			(istreambuf_iterator<char>()));

		string PublicKey = temp[0];

		//encrypt file
		string cipher;
		byte* key = new byte[KELEN];
		byte* iv = NULL;
		int lenIV = (isAES) ? AES::BLOCKSIZE : DES_EDE3::BLOCKSIZE;

		prng.GenerateBlock(key, KELEN);
		iv = new byte[lenIV];
		prng.GenerateBlock(iv, lenIV);

		//Encrypt(message, key, iv, isAES);
		cipher = Encrypt(message, key, iv, isAES);
		//encrypt secret key by public key of receiver
		string kiv = string(key, key + KELEN) + string(iv, iv + lenIV);
		string ckiv;

		RSA::PublicKey publicKey;
		LoadKey(PublicKey, publicKey);
		RSAES_OAEP_SHA_Encryptor e(publicKey);

		StringSource ss1(kiv, true, new PK_EncryptorFilter(prng, e, new StringSink(ckiv)));
		int ll = ckiv.length();
		string lenCkiv((char*)&ll, ((char*)&ll) + sizeof(int));
		//final cipher
		string fcipher = string(1, char(isAES)) + lenCkiv + ckiv + cipher;
		ofs << fcipher;
		ofs.close();

		if (key != NULL) 
			delete[]key;
		if (iv != NULL)	
			delete[]iv;
		
		return true;
	}
	catch (string e)
	{
		cout << e << endl;
		return false;
	}
	catch (const std::exception& e)
	{
		cout << e.what() << endl;
		return false;
	}
	catch (...)
	{
		cout << UNERR;
		return false;
	}
	
}

bool decryptFile(const string& src, const string& dest, const string& PrivateKey)
{
	try
	{
		ifstream ifs(src, std::ios::binary);
		if (!ifs.good())
			throw string(NOINPUT);

		string cipher((istreambuf_iterator<char>(ifs)), (istreambuf_iterator<char>()));

		int ll = *(int*)(cipher.c_str() + 1);
		int prefix = 1 + sizeof(int)+ll;

		bool isAES = int(cipher[0]) > 0;
		//prefix += isAES? AES::BLOCKSIZE: DES_EDE2::BLOCKSIZE; // 1 + KELEN + BLOCKSIZE
		string ckiv = cipher.substr(1 + sizeof(int), ll);
		cipher = cipher.substr(prefix);

		//get private key
		//string PrivateKey = LogIn("something here I dont know");
		RSA::PrivateKey privateKey;
		LoadKey(PrivateKey, privateKey);

		//restore symmetric key and iv
		string kiv;
		RSAES_OAEP_SHA_Decryptor d(privateKey);
		StringSource ss2(ckiv, true, new PK_DecryptorFilter(prng, d, new StringSink(kiv)));

		byte *key = new byte[KELEN];
		byte *iv = new byte[kiv.length() - KELEN];

		memcpy(key, kiv.c_str(), KELEN);
		memcpy(iv, kiv.c_str()+KELEN, kiv.length() - KELEN);

		string message = Decrypt(cipher, key, iv, isAES);

		//create plaintext-file
		ofstream ofs(dest, std::ios::binary);
		if (!ofs.good())
		{
			if (ifs.is_open()) 
				ifs.close();
			if (key != NULL) 
				delete[]key;
			if (iv != NULL)	
				delete[]iv;
			throw string(NOOUTPUT);
		}
			
		ofs << message;
		ofs.close();

		if (key != NULL) 
			delete[]key;
		if (iv != NULL)
			delete[]iv;
		return true;
	}
	catch (string e)
	{
		cout << e << endl;
		return false;
	}
	catch (const std::exception& e)
	{
		cout << e.what() << endl;
		return false;
	}
	catch (...)
	{
		cout << UNERR << endl;
		return false;
	}
	
}

//static bool verifySignature(const string& message, const string& signature, DSA::PublicKey publicKey)
//{
//	DSA::Verifier verifier(publicKey);
//	bool result = false;
//	StringSource ss(message + signature, true,
//		new SignatureVerificationFilter(
//		verifier,
//		new ArraySink(
//		(byte*)&result, sizeof(result)),
//		SignatureVerificationFilter::Flags::PUT_RESULT | SignatureVerificationFilter::Flags::SIGNATURE_AT_END
//		)
//		);
//
//	return result;
//}
