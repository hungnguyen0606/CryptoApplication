^CÁ“¡k§Ñ "symmetry.h"

typedef bool (*MakePairs)(RSA::PrivateKey&, RSA::PublicKey&);
string PASSPHR;


bool LoadKey(const string& str, CryptoMaterial& key)
{
	ByteQueue queue;
	istringstream iss(str);
	FileSource file(iss, true);
	file.TransferTo(queue);
	queue.MessageEnd();
	key.Load(queue);
	return true;
}

string SaveKey(const CryptoMaterial& key)
{
	ByteQueue queue;
	key.Save(queue);
	ostringstream oss;
	FileSink file(oss);
	queue.CopyTo(file);
	file.MessageEnd();
	return oss.str();
}


static bool RandomPairs(RSA::PrivateKey& pri, RSA::PublicKey& pub)
{
	pri.GenerateRandomWithKeySize(prng, RSAKE);
	pub = RSA::PublicKey(pri);
	return true;
}

bool SaveRandomPairs()
{
	RSA::PrivateKey pri;
	RSA::PublicKey pub;
	RandomPairs(pri, pub);

	ofstream ofsr(PRIKL, std::ios::binary);
	ofsr << SaveKey(pri);
	ofsr.close();

	ofstream ofsu(PUBKL, std::ios::binary);
	ofsu << SaveKey(pub);
	ofsu.close();

	return true;
}

static bool LoadPairs(RSA::PrivateKey& pri, RSA::PublicKey& pub)
{
	ifstream ifsr(PRIKL, std::ios::binary);
	if (!ifsr.good())
		return false;
	string prikey((istreambuf_iterator<char>(ifsr)),
		(istreambuf_iterator<char>()));
	ifsr.close();

	LoadKey(prikey, pri);
	pub = RSA::PublicKey(pri);

	ifstream ifsu(PUBKL, std::ios::binary);
	if (!ifsu.good())
		return false;
	string pubkey((istreambuf_iterator<char>(ifsu)),
		(istreambuf_iterator<char>()));
	ifsu.close();
	
	if (pubkey != SaveKey(pub))
		return false;
	return true;
}

static vector<string> SaveRecord(const vector<string>& path,
	bool encrypt, MakePairs mp = RandomPairs)
{
	if (!encrypt)
	{
		ifstream ifs(path[0]);
		if (!ifs.good())
			return vector<string>();

		vector<string> fields =
			vector<string>(FIELD, "");

		int count = 0;
		while (ifs.good())
		{
			string line;
			getline(ifs, line);
			while (true)
			{
				int pos = line.find(DELIM);
				if (pos == string::npos)
					break;
				line.replace(pos, sizeof(DELIM) - 1, "");
			}
			fields[count++] = line;
		}
		ifs.close();

		if (count != SALTY || fields[EMAIL].size()
			< 1 || fields[PAPHR].size() < 1)
			return vector<string>();

		// system(("del \"" + path[0] + "\"").c_str());
		return fields;
	}

	vector<string>& fields = (vector<string>&)path;

	string pass = fields[PAPHR];
	byte salt[KELEN + 1]; salt[KELEN] = 0;
	prng.GenerateBlock(salt, KELEN);
	fields[SALTY] = string((char*)salt, KELEN);

	string input = pass + fields[SALTY];
	byte digest[SHA256::DIGESTSIZE + 1];
	digest[SHA256::DIGESTSIZE] = 0;
	SHA256().CalculateDigest(digest,
		(byte*)input.c_str(), input.size());
	fields[PAPHR] = string((char*)digest, SHA256::DIGESTSIZE);

	RSA::PrivateKey pri;
	RSA::PublicKey pub;
	if (!mp(pri, pub))
		RandomPairs(pri, pub);
	fields[PUBKE] = SaveKey(pub);

	string plain = SaveKey(pri), cipher; 
	byte key[KELEN + 1]; byte iv[AES::BLOCKSIZE + 1];
	strcpy((char*)key, input.substr(0, KELEN).c_str());
	strcpy((char*)iv, fields[SALTY].substr(0, AES::BLOCKSIZE).c_str());
	fields[PRIKE] = Encrypt(plain, key, iv);

	string rec;
	for (int i = 0; i < FIELD; ++i)
		rec += fields[i] + DELIM;
	int len = rec.size();
	for (int i = sizeof(DELIM) - 1; i >= 1; --i)
		rec[len - i] = '\n';
	return vector<string>(1, rec);
}

bool SignUp(const string& path)
{
	vector<string> rec =
		SaveRecord(vector<string>(1, path), false);
	if (rec.size() == 0)
		return false;

	vector<string> index =
		SearchDatabase(rec[EMAIL], EMAIL);
	if (index.size() == FIELD)
		return false;
	
	vector<string> record =
		SaveRecord(rec, true);
	AddToDatabase(record[0]);
	
	return true;
}

string LogIn(const string& path)
{
	vector<string> rec =
		SaveRecord(vector<string>(1, path), false);
	if (rec.size() == 0)
		return "";

	vector<string> index =
		SearchDatabase(rec[EMAIL], EMAIL);
	if (index.size() != FIELD)
		return "";

	string pass = rec[PAPHR];
	string input = pass + index[SALTY];
	byte digest[SHA256::DIGESTSIZE + 1];
	digest[SHA256::DIGESTSIZE] = 0;
	SHA256().CalculateDigest(digest,
		(byte*)input.c_str(), input.size());

	if (index[PAPHR] != string((char*)digest, SHA256::DIGESTSIZE))
		return "";
	PASSPHR = pass;// cout << PASSPHR;

	string cipher = index[PRIKE];
	byte key[KELEN + 1]; byte iv[AES::BLOCKSIZE + 1];
	strcpy((char*)key, input.substr(0, KELEN).c_str());
	strcpy((char*)iv, index[SALTY].substr(0, AES::BLOCKSIZE).c_str());
	string plain = Decrypt(cipher, key, iv);

	return plain;
}

bool Update(const string& path)
{
	vector<string> rec =
		SaveRecord(vector<string>(1, path), false);
	if (rec.size() == 0)
		return false;

	vector<string> index =
		SearchDatabase(rec[EMAIL], EMAIL);
	if (index.size() != FIELD)
		return false;

	if (rec[PAPHR] != PASSPHR)
	{
		for (int i = 1; i < PAPHR; ++i)
			if (rec[i].size() < 1)
				rec[i] = index[i];
		vector<string> record;
		if (rec[PAPHR] == "#")
		{
			rec[PAPHR] = PASSPHR;
			record = SaveRecord(rec, true, LoadPairs);
		}
		else
			record = SaveRecord(rec, true);
		AddToDatabase(record[0]);
	}
	else
	{
		string record = index[0] + DELIM;
		for (int i = 1; i < FIELD; ++i)
		{
			if (rec[i].size() >= 1 && i != PAPHR)
				record += rec[i] + DELIM;
			else
				record += index[i] + DELIM;
		}
		int len = record.size();
		for (int i = sizeof(DELIM) - 1; i >= 1; --i)
			record[len - i] = '\n';
		AddToDatabase(record);
	}

	// PASSPHR = "";
	return true;
}