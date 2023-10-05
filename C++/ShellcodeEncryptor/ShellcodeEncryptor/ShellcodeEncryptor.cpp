#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <regex>
#include "structures.h"

using namespace std;

int main(int argc, char* argv[])
{
	if (argc != 3) {
		cout << "Usage: ShellcodeEncryptor.exe <file> <16-char key>";
		return -1;
	}
	ifstream t(argv[1]);
	string key_s = argv[2];
	while (key_s.length() < 16) {
		key_s += "0";
	}
	const char* cstr = key_s.c_str();
	istringstream iss(cstr);
	unsigned char key[16];
	if (iss >> key) {
		stringstream ss;
		ss << t.rdbuf();
		string shellcode = ss.str();
		shellcode = shellcode.substr(shellcode.find_last_of("=") + 1, shellcode.size());
		regex reg("\t|\"|\n|;| |\\\\|x");
		shellcode = regex_replace(shellcode, reg, "");
		int len = shellcode.length() / 2;
		unsigned char* buf = new unsigned char[len];
		const char* cstr = shellcode.c_str();
		for (int i = 0; i < len; i++) {
			sscanf_s(cstr, "%2hhx", &buf[i]);
			cstr += 2 * sizeof(char);
		}
		int originalLen = len;
		int paddedMessageLen = originalLen;
		if ((paddedMessageLen % 16) != 0) {
			paddedMessageLen = (paddedMessageLen / 16 + 1) * 16;
		}
		unsigned char* paddedMessage = new unsigned char[paddedMessageLen];
		for (int i = 0; i < paddedMessageLen; i++) {
			if (i >= originalLen) {
				paddedMessage[i] = 0;
			}
			else {
				paddedMessage[i] = buf[i];
			}
		}
		unsigned char* encryptedMessage = new unsigned char[paddedMessageLen];
		unsigned char expandedKey[176];
		KeyExpansion(key, expandedKey);
		for (int i = 0; i < paddedMessageLen; i += 16) {
			AESEncrypt(paddedMessage + i, expandedKey, encryptedMessage + i);
		}
		printf("Key: %s (", key);
		for (int i = 0; i < sizeof key; i++) {
			cout << hex << (int)key[i];
		}
		cout << ")\n\n";
		printf("unsigned char buf[] = \n\t\"");
		for (int i = 0; i < paddedMessageLen; i++) {
			if ((i + 1) % 14 == 0) {
				cout << "\\x" << std::setfill('0') << std::setw(2) << hex << (int)encryptedMessage[i];
				cout << "\"\n\t\"";
			}
			else {
				cout << "\\x" << std::setfill('0') << std::setw(2) << hex << (int)encryptedMessage[i];
			}
		}
		cout << "\";";
		delete[] paddedMessage;
		delete[] encryptedMessage;
		return 0;
	}
	return -1;
}
