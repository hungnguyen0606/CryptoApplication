#include "FileEnc.h"

using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::ArraySink;


std::string makeSignature(const string& path, string PrivateKey)
{
	DSA::PrivateKey privateKey;
	//call load key
	bool isOk = LoadKey(PrivateKey, privateKey);
	assert(isOk);
    //------------------------------------------------
	ifstream ifs(path, std::ios::binary);
	if (!ifs.good())
		return string();

	string message((istreambuf_iterator<char>(ifs)), 
		(istreambuf_iterator<char>()));
	string ret;

	DSA::Signer signer(privateKey);
	StringSource ss1(message, true,
		new SignerFilter(prng, signer,
		new StringSink(ret)
		) // SignerFilter
		); // StringSource

	return ret;
}

static bool verifySignature(const string& message, const string& signature, DSA::PublicKey publicKey)
{
	DSA::Verifier verifier(publicKey);
	bool result = false;
	StringSource ss(message + signature, true,
		new SignatureVerificationFilter(
		verifier,
		new ArraySink(
		(byte*)&result, sizeof(result)),
		SignatureVerificationFilter::Flags::PUT_RESULT | SignatureVerificationFilter::Flags::SIGNATURE_AT_END
		)
		);

	return result;
}


int verifySignature(const string& pathFile, const string& pathSign)
{
	ifstream ifsM(pathFile, std::ios::binary);
	ifstream ifsS(pathSign, std::ios::binary);

	if (!ifsM.good() || !ifsS.good())
		return false;

	string message((istreambuf_iterator<char>(ifsM)),
		(istreambuf_iterator<char>()));

	string signature((istreambuf_iterator<char>(ifsS)),
		(istreambuf_iterator<char>()));

	vector<string> data = SearchDatabase("", -1, PUBKE);
	for (int i = 0; i < data.size(); ++i)
	{
		string temp = data[i].substr(data[i].find_last_of(DELIM) + 1);
		temp.pop_back();

		DSA::PublicKey myKey;
		LoadKey(data[i], myKey);
		if (verifySignature(message, signature, myKey))
		{
			//string name = data[i].substr(data[i].find_first_of(DELIM) + 1);
			vector<string> name = SearchDatabase(data[i], PUBKE, 1);
			assert(name.size() > 0);
			cout << name[0] << " signed this file.";
			return i;
		}
	}
	return -1;
}

bool encryptFile(const string& src, const string& dest, bool isAES, const string& email)
{
	vector<string> temp = SearchDatabase(email, 0, 8);
	
	if (temp.size() < 1)
		return false;
	ifstream ifs(src, std::ios::binary);

	if (!ifs.good())
		return false;

	string message((istreambuf_iterator<char>(ifs)),
		(istreambuf_iterator<char>()));
	
	string PublicKey = temp[0];

	//encrypt file
	string cipher;
	byte* key = new byte[KELEN];
	byte* iv;
	int lenIV = (isAES)? AES::BLOCKSIZE: DES_EDE2::BLOCKSIZE;

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
	
	StringSource ss1(kiv, true, new PK_EncryptorFilter(prng, e,	new StringSink(ckiv)));
	
	//final cipher
	string fcipher = string(1, char(isAES)) + ckiv + cipher;
	
	return true;
}

bool decryptFile(const string& src, const string& dest, const string& PrivateKey)
{
	int prefix = KELEN + 1;
	string cipher;
	bool isAES = int(cipher[0]) > 0;
	prefix += isAES? AES::BLOCKSIZE: DES_EDE2::BLOCKSIZE; // 1 + KELEN + BLOCKSIZE
	string ckiv = cipher.substr(1, prefix - 1);
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
	memcpy(iv, kiv.c_str(), kiv.length() - KELEN);

	string message = Decrypt(cipher, key, iv, isAES);

	//create plaintext-file
	ofstream ofs(dest, std::ios::binary);
	if (!ofs.good())
		return false;
	ofs << message;
	ofs.close();
	
	return true;
}
