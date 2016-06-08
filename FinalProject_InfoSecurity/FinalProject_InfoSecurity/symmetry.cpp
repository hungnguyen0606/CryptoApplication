#include "symmetry.h"


string Encrypt(const string& plain, byte* key, byte* iv, bool aes)
{
	StreamTransformation* e = NULL;
	if (aes)
	{
		e = new CBC_Mode<AES>::Encryption;
		((CBC_Mode<AES>::Encryption*)e)->SetKeyWithIV(key, KELEN, iv, AES::BLOCKSIZE);
	}
	else
	{
		e = new CBC_Mode<DES_EDE3>::Encryption;
		((CBC_Mode<DES_EDE3>::Encryption*)e)->SetKeyWithIV(key, KELEN, iv, DES_EDE3::BLOCKSIZE);
	}

	string cipher;
	StringSource s(plain, true,
		new StreamTransformationFilter(*e,
		new StringSink(cipher),
		CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING));
	delete e;

	return cipher;
}

string Decrypt(const string& cipher, byte* key, byte* iv, bool aes)
{
	StreamTransformation* d = NULL;
	if (aes)
	{
		d = new CBC_Mode<AES>::Decryption;
		((CBC_Mode<AES>::Encryption*)d)->SetKeyWithIV(key, KELEN, iv, AES::BLOCKSIZE);
	}
	else
	{
		d = new CBC_Mode<DES_EDE3>::Decryption;
		((CBC_Mode<DES_EDE3>::Encryption*)d)->SetKeyWithIV(key, KELEN, iv, DES_EDE3::BLOCKSIZE);
	}

	string plain;
	StringSource s(cipher, true,
		new StreamTransformationFilter(*d,
		new StringSink(plain),
		CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING));
	delete d;

	return plain;
}