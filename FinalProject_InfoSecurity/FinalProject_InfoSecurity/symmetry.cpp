#include "symmetry.h"


string Encrypt(const string& plain, byte* key, byte* iv, bool aes)
{
	StreamTransformation* e = NULL;
	if (aes)
	{
		e = new CBC_Mode<AES>::Encryption;
		((CBC_Mode<AES>::Encryption*)e)->SetKeyWithIV(key, KELEN, iv);
	}
	else
	{
		e = new CBC_Mode<DES_EDE2>::Encryption;
		((CBC_Mode<DES_EDE2>::Encryption*)e)->SetKeyWithIV(key, KELEN, iv);
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
		((CBC_Mode<AES>::Encryption*)d)->SetKeyWithIV(key, KELEN, iv);
	}
	else
	{
		d = new CBC_Mode<DES_EDE2>::Decryption;
		((CBC_Mode<DES_EDE2>::Encryption*)d)->SetKeyWithIV(key, KELEN, iv);
	}

	string plain;
	StringSource s(cipher, true,
		new StreamTransformationFilter(*d,
		new StringSink(plain),
		CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING));
	delete d;

	return plain;
}