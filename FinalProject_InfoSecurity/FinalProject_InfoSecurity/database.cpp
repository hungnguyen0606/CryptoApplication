#include "symmetry.h"

extern string MAIVE;
extern AutoSeededRandomPool prng;

vector<string> data; int pivot = -1;


bool LoadDatabase()
{
	if (data.size() != 0)
		return true;
	
	ifstream ifs(DATAL, std::ios::binary);
	if (!ifs.good())
		return true;

	string cipher((istreambuf_iterator<char>(ifs)),
		(istreambuf_iterator<char>()));
	ifs.close();

	MAIVE = cipher.substr(0, AES::BLOCKSIZE);
	cipher = cipher.substr(AES::BLOCKSIZE);

	byte key[KELEN + 1]; strcpy((char*)key, MAPAS);
	byte iv[AES::BLOCKSIZE + 1]; strcpy((char*)iv, MAIVE.c_str());

	string plain = Decrypt(cipher, key, iv);

	string end(sizeof(DELIM) - 1, '\n');
	int pos = plain.find(end), len = end.size();
	while (pos != string::npos)
	{
		data.push_back(plain.substr(0, pos + len));
		plain.erase(0, pos + len);
		pos = plain.find(end);
	}

	return true;
}

bool SaveDatabase()
{
	string plain, cipher;

	int len = data.size();
	for (int i = 0; i < len; ++i)
		plain += data[i];
	
	byte key[KELEN + 1];
	strcpy((char*)key, MAPAS);
	byte iv[AES::BLOCKSIZE + 1]; iv[AES::BLOCKSIZE] = 0;
	prng.GenerateBlock(iv, AES::BLOCKSIZE);
	MAIVE = string((char*)iv, AES::BLOCKSIZE);
	
	cipher = Encrypt(plain, key, iv);
	
	ofstream ofs(DATAL, std::ios::binary);
	ofs << MAIVE + cipher;
	ofs.close();

	pivot = -1;
	data.clear();
	return true;
}


static vector<string> ParseRecord(const string& record)
{
	vector<string> rec;
	string line = record;
	int pos = line.find(DELIM),
		len = sizeof(DELIM) - 1;

	for (int i = len; i >= 1; --i)
		line.pop_back();
	while (pos != string::npos)
	{
		rec.push_back(line.substr(0, pos));
		line.erase(0, pos + len);
		pos = line.find(DELIM);
	}
	rec.push_back(line);

	return rec;
}

vector<string> CurrentInDatabase()
{
	if (pivot < 0 || pivot >= (int)data.size())
		return vector<string>();
	return ParseRecord(data[pivot]);
}

bool AddToDatabase(const string& record)
{
	if (record.size() < 1 || record.back() != '\n')
		return false;

	if (!LoadDatabase())
		return false;

	if (pivot < 0 || pivot >= (int)data.size())
		data.push_back(record);
	else
		data[pivot] = record;
	SaveDatabase();

	return true;
}

vector<string> SearchDatabase(const string& key, int col, int ret)
{
	if (ret < -1 || col < -1)
		return vector<string>();

	LoadDatabase();

	vector<string> whole;
	int len = data.size();
	for (pivot = 0; pivot < len; ++pivot)
	{
		vector<string> rec = ParseRecord(data[pivot]);

		if (ret >= 0)
			whole.push_back(rec[ret]);

		if (col >= 0 && key == rec[col])
		{
			if (ret < 0)
				return rec;
			return vector<string>(1, rec[ret]);
		}
	}

	if (col == -1)
		return whole;
	return vector<string>();
}