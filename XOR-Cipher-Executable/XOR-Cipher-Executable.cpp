#include "stdafx.h"
#include <iostream>
#include <string>
#include <fstream>

using namespace std;

typedef struct {

	char* image;
	streampos size;

} PARAMS;

void PrintInstructions();
bool OpenExecutable(string executable, PARAMS *data);
void EncryptExecutable(PARAMS *data);
bool WriteExecutable(PARAMS *data);


int main(int argc, char *argv[])
{

	if (argc != 2) {
		PrintInstructions();
	}

	PARAMS data;

	if (!OpenExecutable(argv[1], &data)) {
		cout << "There was an error opening the specified file." << endl;
		return 0;
	}

	EncryptExecutable(&data);

	if (!WriteExecutable(&data)) {
		cout << "There was an error creating the encrypted file." << endl;
		return 0;
	}

	cout << "crypt.exe created successfully." << endl;
	
    return 0;
}

void PrintInstructions() {
	cout << "-- Crypter POC --" << endl << endl << endl;
	cout << "encrypt.exe [programtocrypt.exe]" << endl << endl;
	cout << "Creates crypt.exe, to be included as resource in stub program." << endl << endl;

}

bool OpenExecutable(string executable, PARAMS *data) {

	ifstream infile(executable, ios::in | ios::binary | ios::ate);

	if (infile.is_open())
	{
		data->size = infile.tellg();
		data->image = new char[data->size];
		infile.seekg(0, ios::beg);
		infile.read(data->image, data->size);
		infile.close();
		return true;
	}

	return false;

}

void EncryptExecutable(PARAMS *data) {

	int key = 128;

	for (int i = 0; i < data->size; i++) {
		data->image[i] ^= key;
	}

}

bool WriteExecutable(PARAMS *data) {

	ofstream f("crypt.exe", std::ios::out | std::ios::binary);

	if (f.is_open()) {
		f.write((char*)data->image, data->size);
		f.close();
		return true;
	}

	return false;
}
