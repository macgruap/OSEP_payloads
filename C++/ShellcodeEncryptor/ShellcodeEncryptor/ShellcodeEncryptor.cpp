#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <regex>
#include <format>
#include "structures.h"

using namespace std;

int main(int argc, char* argv[])
{
	if (argc != 3) {
		cout << "Usage: ShellcodeEncryptor.exe <file> <16-char key>";
		return -1;
	}
	string origFile = argv[1];
	string key_s = argv[2];
	
	ifstream t(origFile);
	t.seekg(0, std::ios::end);
	std::streampos fileSize = t.tellg();
	t.seekg(0, std::ios::beg);

	while (key_s.length() < 16) {
		key_s += "0";
	}
	const char* cstr = key_s.c_str();
	istringstream iss(cstr);
	unsigned char key[16];
	if (iss >> key) {
		string shellcode, shellcode_;
		shellcode_.resize(fileSize);
		t.read(&shellcode_[0], fileSize);
		int len = 0;
		if (origFile.substr(origFile.find_last_of('.'), origFile.length()) == ".bin") {
			printf("Processing payload...\n");
			for (int i = 0; i < fileSize; i++) {
				shellcode += std::format("{:02x}", (int)(uint8_t)shellcode_[i]);
			}
		}
		else {
			shellcode = shellcode_;
			shellcode = shellcode.substr(shellcode.find_last_of("=") + 1, shellcode.size());
			shellcode.erase(remove(shellcode.begin(), shellcode.end(), '\t'), shellcode.end());
			shellcode.erase(remove(shellcode.begin(), shellcode.end(), '\"'), shellcode.end());
			shellcode.erase(remove(shellcode.begin(), shellcode.end(), '\n'), shellcode.end());
			shellcode.erase(remove(shellcode.begin(), shellcode.end(), ';'), shellcode.end());
			shellcode.erase(remove(shellcode.begin(), shellcode.end(), ' '), shellcode.end());
			shellcode.erase(remove(shellcode.begin(), shellcode.end(), '\\'), shellcode.end());
			shellcode.erase(remove(shellcode.begin(), shellcode.end(), 'x'), shellcode.end());
		}

		len = (shellcode.find_last_not_of('\x00')+1) / 2;

 		unsigned char* buf = new unsigned char[len];
		cout << "0%";
		const char* cstr = shellcode.c_str();
		float ref = 0;
		for (int i = 0; i < len; i++) {
			sscanf_s(cstr, "%2hhx", &buf[i]);
			cstr += 2 * sizeof(char);
			float percent = ((int)i / (int)len) * 100;
			if (percent >= ref+0.1) {
 				printf("\33[2K\r");
				cout << percent << "%";
				ref = percent;
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
