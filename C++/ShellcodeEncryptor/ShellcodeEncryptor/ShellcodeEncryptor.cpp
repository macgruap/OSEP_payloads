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
		printf("Processing payload...\n");
		shellcode = shellcode.substr(shellcode.find_last_of("=") + 1, shellcode.size());
		shellcode.erase(remove(shellcode.begin(), shellcode.end(), '\t'), shellcode.end());
		shellcode.erase(remove(shellcode.begin(), shellcode.end(), '\"'), shellcode.end());
		shellcode.erase(remove(shellcode.begin(), shellcode.end(), '\n'), shellcode.end());
		shellcode.erase(remove(shellcode.begin(), shellcode.end(), ';'), shellcode.end());
		shellcode.erase(remove(shellcode.begin(), shellcode.end(), ' '), shellcode.end());
		shellcode.erase(remove(shellcode.begin(), shellcode.end(), '\\'), shellcode.end());
		shellcode.erase(remove(shellcode.begin(), shellcode.end(), 'x'), shellcode.end());
		int len = shellcode.length() / 2;
		unsigned char* buf = new unsigned char[len];
		cout << "0%";
		const char* cstr = shellcode.c_str();
		int ref = 0;
		for (int i = 0; i < len; i++) {
			sscanf_s(cstr, "%2hhx", &buf[i]);
			cstr += 2 * sizeof(char);
			float percent = ((float)i / (float)len) * 100;
			if ((int)percent >= ref+10) {
 				printf("\33[2K\r");
				cout << (int) percent << "%";
				ref = (int)percent;
			}
 		}
		printf("\33[2K\r");
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
		printf("Done!\n\nKey: %s (", key);
		for (int i = 0; i < sizeof key; i++) {
			cout << hex << (int)key[i];
		}
		cout << ")\n\n";

		if (paddedMessageLen < 4096) {
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
		}
		else {
			ofstream outFile;
			ostringstream content;

			string origFile = argv[1];
			string path = origFile.substr(0, origFile.find_last_of("\\"))+"\\encPayload.txt";

			printf("Encrypted payload too big to be displayed! Dumping it to %s...\n", path.c_str());
			
			content << "unsigned char buf[] = \n\t\"";
			bool AAA = false;
			for (int i = 0; i < paddedMessageLen; i++) {
				if ((i + 1) % 14 == 0) {
					content << "\\x" << std::setfill('0') << std::setw(2) << hex << (int)encryptedMessage[i];
					content << "\"\n\t\"";
				}
				else {
					content << "\\x" << std::setfill('0') << std::setw(2) << hex << (int)encryptedMessage[i];
				}
			}
			content << "\";";
			outFile.open(path);
			outFile << content.str();
			outFile.close();
			printf("Done!");
		}
		return 0;
	}
	return -1;
}
