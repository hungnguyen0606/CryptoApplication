// Inspired by the sample codes from multiple HTML and ZIP files:
// https://cryptopp.com/wiki/RSA_Cryptography
// https://cryptopp.com/wiki/Hash_Functions#The_SHA_algorithm
// AES-CBC-Filter.zip on https://cryptopp.com/wiki/Advanced_Encryption_Standard
// https://cryptopp.com/wiki/Keys_and_Formats#Generating.2C_Validating.2C_Saving.2C_and_Loading_Keys

#include "symmetry.h"
#include "FileEnc.h"
string MAPUB = "";
string MAPRI = "";
int ARGS[] = {0, 3, 4, 4, 4, 5, 5, 4, 5};
string MAIVE = "0123456789ABCDEF";
AutoSeededRandomPool prng;


int main(int argc, char* argv[])
{
	AssignMasterPairs();

	if (argc == 2 && atoi(argv[1]) == KEYMK)
	{
		SaveRandomPairs();
		cout << "Done Making Keys !!!" << endl;
		return 0;
	}

	if (argc < 3)
	{
		cout << "Syntax Error !!!" << endl;
		return 1;
	}

	int task = atoi(argv[1]);
	if (task > 8 || task <= 0 || argc != ARGS[task])
	{
		cout << "Syntax Error !!!" << endl;
		return 1;
	}

	
	if (task == SIGUP)
	{
		if (!SignUp(string(argv[2])))
			cout << "Syntax Error OR Account Existed !!!" << endl;
		else
			cout << "Signup Successfully !!!" << endl;
		cin >> task;
		return 0;
	}

	string result = LogIn(string(argv[2]));
	if (result == "")
	{
		cout << "Login Unsuccessfully !!!" << endl;
		return 0;
	}

	switch (task)
	{
	case ACCUP: case KEYIM:
		if (!Update(string(argv[3])))
			cout << "Syntax Error !!!" << endl;
		break;
	case ACCEX:
	{
		vector<string> record = CurrentInDatabase();
		if (record.size() != FIELD)
		{
			cout << "Database Error !!!" << endl;
			break;
		}
		
		ofstream ofs(argv[3], std::ios::binary);
		if (!ofs.good())
		{
			cout << "Output Error !!!" << endl;
			break;
		}
		
		for (int i = 0; i < PAPHR; ++i)
			ofs << record[i] << endl;
		for (int i = PAPHR; i < FIELD; ++i)
			ofs << record[i] + DELIM << endl;
		ofs.close();
		break;
	}
	case DOCEN:
	{
		string src(argv[3]);
		string dest(argv[4]);
		string email("what is the email");
		int choice = atoi(argv[5]);
		bool isAES;
		bool err = false;
		switch (choice)
		{
		case 0:
			isAES = true;
			break;
		case 1:
			isAES = false;
			break;
		default: 
			err = true;
		}
		if (err)
		{
			cout << "Enter 0 to use AES, 1 to use 3DES.";
			break;
		}
		if (encryptFile(src, dest, isAES, email))
			cout << "Finished encrypting the file.";
		else
			cout << "Failed to encrypt the file.";
		break;
	}
		
	case DOCDE:
	{
		if (decryptFile(string(argv[3]), string(argv[4]), result))
			cout << "Finished decrypting the file.";
		else
			cout << "Failed to decrypt the file.";
		break;
	}
		
	case SIGMK:
	{
	    string src(argv[3]);
		string dest = src + ".sig";
		string sig = makeSignature(src, result);
		
		if (sig == "")
		{
			cout << "Cannot create file's signature.";
			break;
		}
		ofstream ofs(dest, std::ios::binary);
		ofs << sig;
		ofs.close();
		cout << "Finished creating the signature.";
		break;
	}
		
	case SIGCK:
	{
		string src(argv[3]);
		string dest(argv[4]);
		if (verifySignature(src, dest))
			cout << "The file's signature is correct.";
		else
			cout << "The file's signature is incorrect.";
		break;
	}
		
	default:
		cout << "No Support !!!" << endl;
	}

	cout << "Task Complete !!!" << endl;
	cin >> task;


	/*if (argc != 7 && argc != 4)
		return 1;

	AutoSeededRandomPool prng;

	string crypt = string(argv[1]), 
		input = string(argv[2]),
		output = string(argv[3]);
	
	ifstream ifs(input, std::ios::binary);
	if (!ifs.good())
	{
		cout << "Cannot open the input file !!!" << endl;
		return 1;
	}

	ofstream ofs(output, std::ios::binary);
	if (!ofs.good())
	{
		cout << "Cannot open the output file !!!" << endl;
		ifs.close();
		return 1;
	}
	

	if (crypt == "e" && argc == 7)
	{
		cout << "Encryption :" << endl;

		string calgor = string(argv[4]),
			padd = string(argv[5]),
			moofop = string(argv[6]);
		string plain((istreambuf_iterator<char>(ifs)),
			(istreambuf_iterator<char>())), cipher;
		ifs.close();

		if ((calgor != "3DES" && calgor != "AES") || (padd != "X923"
			&& padd != "PKCS7") || (moofop != "CBC" && moofop != "OFB"))
		{
			cout << "No support !!!" << endl;
			ofs.close();
			return 1;
		}
		

		cout << "Input password (16 bytes): ";
		string inKey; cin >> inKey;
		if (inKey.length() <= 16)
			inKey.append(16 - inKey.length(), 'V');
		else
			inKey.erase(16, string::npos);
		byte* key = new byte[16]; strcpy((char*)key, inKey.c_str());


		int blockSize = 16;
		if (calgor == "3DES")
			blockSize = 8;
		int paddSize = blockSize - plain.length() % blockSize;
		if (padd == "X923")
			plain.append(paddSize - 1, 0);
		else
			plain.append(paddSize - 1, paddSize);
		plain.push_back((char)paddSize);


		string outIV;
		StreamTransformation* e = NULL;
		if (calgor == "3DES")
		{
			byte iv[DES_EDE2::BLOCKSIZE];
			prng.GenerateBlock(iv, sizeof(iv));
			outIV = string((char*)iv);

			if (moofop == "CBC")
			{
				auto tmp = new CBC_Mode<DES_EDE2>::Encryption;
				tmp->SetKeyWithIV(key, 16, iv);
				e = tmp;
			}
			else
			{
				auto tmp = new OFB_Mode<DES_EDE2>::Encryption;
				tmp->SetKeyWithIV(key, 16, iv);
				e = tmp;
			}
		}
		else
		{
			byte iv[AES::BLOCKSIZE];
			prng.GenerateBlock(iv, sizeof(iv));
			outIV = string((char*)iv);

			if (moofop == "CBC")
			{
				auto tmp = new CBC_Mode<AES>::Encryption;
				tmp->SetKeyWithIV(key, 16, iv);
				e = tmp;
			}
			else
			{
				auto tmp = new OFB_Mode<AES>::Encryption;
				tmp->SetKeyWithIV(key, 16, iv);
				e = tmp;
			}
		}


		StringSource s(plain, true,
			new StreamTransformationFilter(*e,
			new StringSink(cipher),
			CryptoPP::BlockPaddingSchemeDef::NO_PADDING));
		delete e;
		delete key;


		cipher += ".";
		cipher += calgor;
		cipher += ".";
		cipher += padd;
		cipher += ".";
		cipher += moofop;
		cipher += ".";
		cipher += outIV;
		ofs << cipher;
		ofs.close();

	}
	else if (crypt == "d" && argc == 4)
	{
		cout << "Decryption :" << endl;

		string cipher((istreambuf_iterator<char>(ifs)),
			(istreambuf_iterator<char>())), plain;
		ifs.close();


		int pos; pos = cipher.find_last_of('.');
		if (pos == string::npos)
		{
			cout << "Wrong format !!!" << endl;
			ofs.close();
			return 1;
		}
		string outIV = cipher.substr(pos + 1);
		cipher.erase(pos, string::npos);

		pos = cipher.find_last_of('.');
		if (pos == string::npos)
		{
			cout << "Wrong format !!!" << endl;
			ofs.close();
			return 1;
		}
		string moofop = cipher.substr(pos + 1);
		cipher.erase(pos, string::npos);

		pos = cipher.find_last_of('.');
		if (pos == string::npos)
		{
			cout << "Wrong format !!!" << endl;
			ofs.close();
			return 1;
		}
		string padd = cipher.substr(pos + 1);
		cipher.erase(pos, string::npos);

		pos = cipher.find_last_of('.');
		if (pos == string::npos)
		{
			cout << "Wrong format !!!" << endl;
			ofs.close();
			return 1;
		}
		string calgor = cipher.substr(pos + 1);
		cipher.erase(pos, string::npos);

		if ((calgor != "3DES" && calgor != "AES") || (padd != "X923"
			&& padd != "PKCS7") || (moofop != "CBC" && moofop != "OFB"))
		{
			cout << "No support !!!" << endl;
			ofs.close();
			return 1;
		}


		cout << "Input password (16 bytes): ";
		string inKey; cin >> inKey;
		if (inKey.length() <= 16)
			inKey.append(16 - inKey.length(), 'V');
		else
			inKey.erase(16, string::npos);
		byte* key = new byte[16]; strcpy((char*)key, inKey.c_str());


		StreamTransformation* d = NULL;
		if (calgor == "3DES")
		{
			byte iv[DES_EDE2::BLOCKSIZE];
			strcpy((char*)iv, outIV.c_str());

			if (moofop == "CBC")
			{
				auto tmp = new CBC_Mode<DES_EDE2>::Decryption;
				tmp->SetKeyWithIV(key, 16, iv);
				d = tmp;
			}
			else
			{
				auto tmp = new OFB_Mode<DES_EDE2>::Decryption;
				tmp->SetKeyWithIV(key, 16, iv);
				d = tmp;
			}
		}
		else
		{
			byte iv[AES::BLOCKSIZE];
			strcpy((char*)iv, outIV.c_str());

			if (moofop == "CBC")
			{
				auto tmp = new CBC_Mode<AES>::Decryption;
				tmp->SetKeyWithIV(key, 16, iv);
				d = tmp;
			}
			else
			{
				auto tmp = new OFB_Mode<AES>::Decryption;
				tmp->SetKeyWithIV(key, 16, iv);
				d = tmp;
			}
		}


		StringSource s(cipher, true,
			new StreamTransformationFilter(*d,
			new StringSink(plain),
			CryptoPP::BlockPaddingSchemeDef::NO_PADDING));
		delete d;
		delete key;


		int blockSize = 16;
		if (calgor == "3DES")
			blockSize = 8;
		int paddSize = (int)plain.back();
		if (paddSize <= 0 || paddSize > blockSize)
		{
			cout << "Wrong format !!!" << endl;
			ofs.close();
			return 1;
		}

		char tail = 0;
		if (padd != "X923")
			tail = (char)paddSize;
		plain.pop_back();
		for (int i = paddSize - 1; i >= 1; --i)
		{
			if (plain.back() != tail)
			{
				cout << "Wrong format !!!" << endl;
				ofs.close();
				return 1;
			}
			plain.pop_back();
		}
		

		ofs << plain;
		ofs.close();

	}
	else
		cout << "Wrong syntax !!!" << endl;*/

	return 0;
}