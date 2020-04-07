/*******************************************************************
*
*   File: AES128Encrypt.cpp
*   Author: Cameron Edmondson
*   Class: CS 4600
*   Project 1: 128 Bit AES Encryption
*   Date last modified: 03/22/2020
*

                                           AES Block Diagram

     ------------------------------------                    ------------------------------------
    |           Plaintext               |                   |               Key                 |
    ------------------------------------                    ------------------------------------
                    |                                                        |
    ------------------------------------                     ------------------------------------
    |           Key Addition           | <----------------- |             Transform             |
    ------------------------------------                    ------------------------------------
                    |                                                       |
     ------------------------------------                                   |
    |           Byte Substitution       |                                   |
    ------------------------------------                                    |
                    |                                                       |
     ------------------------------------                                   |
    |           Mix Coulombs            |                                   |
    ------------------------------------                                    |
                    |                                                       |
     ------------------------------------                     ----------------------------------
    |           Key Addition            | <----------------- |             Transform           |
    ------------------------------------                     ----------------------------------
                    |
     ------------------------------------
    |           CipherText              |
    ------------------------------------
 *
* *****************************************************************/


#include <iostream>
#include <string>
#include <fstream>
#include "aes128_constants.h"
#include <vector>
#include <sstream>
#include <algorithm>

const int BUFFERSIZE = 16;  // Buffer size will remain 16 bytes
unsigned char key[BUFFERSIZE];


void gFunction(unsigned char key[4], int rcon);

using namespace std;

/*
 * Function: roundKeyAddition
 * Purpose:  Exclusive-or the input with the round key.
 *
 *
 *                        a                              roundKey[i]
 *          -----------------------------       -----------------------------
 *          | a0,0 | a0,1 | a0,2 | a0,3 |       | k0,0 | k0,1 | k0,2 | k0,3 |
 *          | a1,0 | a1,1 | a1,2 | a1,3 |  ^=   | k2,0 | k2,1 | k2,2 | k2,3 |
 *          | a2,0 | a2,1 | a2,2 | a2,3 |       | k1,0 | k1,1 | k1,2 | k1,3 |
 *          | a3,0 | a3,1 | a3,2 | a3,3 |       | k3,0 | k3,1 | k3,2 | k3,3 |
 *          -----------------------------       -----------------------------
 *
 *
 */
void roundKeyAddition(const unsigned char *roundKey, unsigned char *a) {
    for (int i = 0; i < BUFFERSIZE; i++) {
        a[i] ^= roundKey[i];    // XOR
    }
}

/*
 * Function: byteSubstitution
 * Purpose:  To substitute every byte in the current state "a"
 *           with another byte from the sbox (substitution box).
 *
 *          -----------------------------
 *          | a0,0 | a0,1 | a0,2 | a0,3 |
 *          | a1,0 | a1,1 | a1,2 | a1,3 |
 *          | a2,0 | a2,1 | a2,2 | a2,3 |
 *          | a3,0 | a3,1 | a3,2 | a3,3 |
 *          -----------------------------
 *
 *          Mapped as follows: a0,0, a1,0, a2,0, a3,0 etc...
 */
void byteSubstitution(unsigned char *a) {
    for (int byte = 0; byte < BUFFERSIZE; byte++) {
        a[byte] = sbox[a[byte]];
    }
}

/*
 * Function: mixColumns
 * Purpose:  Provides diffusion by mixing the input around. Unlike shifRows, mixColumns
 *           performs operations splitting the matrix by columns.
 */
void mixColumns(unsigned char *input) {
    unsigned char tmp[16];
    int i;
    for (i = 0; i < 4; ++i) {
        tmp[(i << 2) + 0] = (unsigned char) (mul2[input[(i << 2) + 0]] ^ mul_3[input[(i << 2) + 1]] ^
                                             input[(i << 2) + 2] ^ input[(i << 2) + 3]);
        tmp[(i << 2) + 1] = (unsigned char) (input[(i << 2) + 0] ^ mul2[input[(i << 2) + 1]] ^
                                             mul_3[input[(i << 2) + 2]] ^ input[(i << 2) + 3]);
        tmp[(i << 2) + 2] = (unsigned char) (input[(i << 2) + 0] ^ input[(i << 2) + 1] ^ mul2[input[(i << 2) + 2]] ^
                                             mul_3[input[(i << 2) + 3]]);
        tmp[(i << 2) + 3] = (unsigned char) (mul_3[input[(i << 2) + 0]] ^ input[(i << 2) + 1] ^ input[(i << 2) + 2] ^
                                             mul2[input[(i << 2) + 3]]);
    }

    for (i = 0; i < 16; ++i)
        input[i] = tmp[i];
}

/*
 * Function: keySchedule
 * Purpose: To produce a set number of round keys from the initial key.
 */
void keySchedule(const unsigned char *original_encryption_key, unsigned char *expanded_keys) {

    int sub_keys = BUFFERSIZE;    // One sub key has been generated so far (the original encryption key)
    int rcon = 1;  // rcon starts at one
    unsigned char temporary_key[4];  // 4 byte temporary variable
    int total_keys = 176; // 11 sub keys of 16 bytes each = 176 bytes

    // Copy the original key as 1st expanded key
    for (int i = 0; i < BUFFERSIZE; i++) {
        expanded_keys[i] = original_encryption_key[i]; // First 16 bytes of expanded key are the same as original key
    }

    // While sub keys generated is less than 11 sub keys continue generating keys
    while (sub_keys < total_keys) {
        // Assign value of previous 4 bytes in expanded key to temporary key
        for (int i = 0; i < 4; i++) {
            temporary_key[i] = expanded_keys[i + sub_keys - 4];
        }
        if (sub_keys % 16 == 0) {   // Use gFunction every 16 bytes
            gFunction(temporary_key, rcon++);
        }

        for (unsigned char k : temporary_key) {
            expanded_keys[sub_keys] = expanded_keys[sub_keys - BUFFERSIZE] ^ k;
            sub_keys++;
        }
    }
}

/*
 * Function: gFunction
 * Purpose:  Perform S-Box transformation, a permutation, and an exclusive-or on
 *           the last word of the previous round key.
 */
void gFunction(unsigned char *temporary_key, int rcon) {
    unsigned char swap_last_element_with_first = temporary_key[0];
    // Rotate 4 bytes left
    for (int i = 0; i < 4; i++) {
        temporary_key[i] = temporary_key[i + 1];
        if (i == 3)
            temporary_key[i] = swap_last_element_with_first;
    }

    // Use sbox on all 4 bytes
    for (int j = 0; j < 4; j++) {
        temporary_key[j] = sbox[temporary_key[j]];
    }

    temporary_key[0] ^= round_constant[rcon]; // XOR (Round Constant - RC)
}


/*
 * Function: shiftRows
 * Purpose: To shift each row of the 128-bit state "a".
 *          Each row is shifted to the left a set amount.
 *          The top row will not shift (remains the same).
 *          The next row is shifted by 1, then 2, etc....
 *
 *               State "a" original                           Temporary state "a_temp"
 *          -----------------------------                  -----------------------------
 *          | a0,0 | a0,1 | a0,2 | a0,3 |                  | a0,0 | a0,1 | a0,2 | a0,3 |
 *          | a1,0 | a1,1 | a1,2 | a1,3 |                  | a1,1 | a1,2 | a1,3 | a1,0 |
 *          | a2,0 | a2,1 | a2,2 | a2,3 | ------------->   | a2,2 | a2,3 | a2,0 | a2,1 |
 *          | a3,0 | a3,1 | a3,2 | a3,3 |                  | a3,3 | a3,0 | a3,1 | a3,2 |
 *          -----------------------------                  -----------------------------
 *
 */
void shiftRows(unsigned char *a) {

    // Holds indices of rows to be shifted
    int shift_row[16] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};

    unsigned char a_temp[BUFFERSIZE];    // Temporarily hold results of state "a"
    int row = 0;  // Keep track of row index
    while (row < BUFFERSIZE) {
        a_temp[row] = a[shift_row[row]];
        row++;
    }

    // Copy results to original state "a"
    for (int i = 0; i < BUFFERSIZE; i++) {
        a[i] = a_temp[i];
    }

}

/*
 * Function: AES128Encrypt
 * Purpose: Encrypt with AES

The encryption phases of AES are as follows:

    Initial Round
        AddRoundKey
    Main Rounds
        SubBytes
        ShiftRows
        MixColumns
        AddRoundKey
    Final Round
        SubBytes
        ShiftRows
        AddRoundKey

 *
 */
void AES128Encrypt(unsigned char *plain_text, unsigned char *key, unsigned char *expandedKey) {
    int rounds = 9;
    unsigned char file_buffer[BUFFERSIZE];
    for (int j = 0; j < BUFFERSIZE; j++) {
        file_buffer[j] = plain_text[j];
    }

    // Initial Round
    roundKeyAddition(key, file_buffer);

    // Main Rounds
    for (int round = 0; round < rounds; round++) {
        byteSubstitution(file_buffer);  // Byte-substitution layer (use sbox map)
        shiftRows(file_buffer); // Shift rows layer
        mixColumns(file_buffer);    // Mix columns layer
        roundKeyAddition(expandedKey + (BUFFERSIZE * (round + 1)), file_buffer);
    }

    //  Final Round
    byteSubstitution(file_buffer);
    shiftRows(file_buffer);
    roundKeyAddition(expandedKey + 160, file_buffer);

    // Copy encrypted state to message
    for (int k = 0; k < BUFFERSIZE; k++) {
        plain_text[k] = file_buffer[k];
    }

}

/*
 * Function: isHexDigit
 * Purpose:  Return true if user input is HEX digits else return false
 */
bool isHexDigit(std::string const &str) {
    for (char i : str)
        if (!std::isxdigit(i))
            return false;
    return true;
}

/*
 * Function: stripWhiteSpace
 * Purpose: Remove all white space from key
 */
string stripWhiteSpace(string &str) {
    str.erase(std::remove(str.begin(), str.end(), ' '), str.end());
    return str;
}

/*
 * Function: stringToLowerCase
 * Purpose: Convert user input to lower case
 */
string stringToLowerCase(string &str) {
    transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
}

/*
 * Function:    getFileSize
 * Purpose: Get file size in bytes, then return size
 */
int getFileSize(const string &source_file_path) {
    ifstream source_file;
    source_file.open(source_file_path, ios::binary | ios::in | ios::ate);    // Open file in binary mode
    // Get file size in bytes
    source_file.seekg(0, ios::end);
    int file_size = source_file.tellg();
    source_file.seekg(0, ios::beg);
    source_file.close();
    return file_size;
}

/*
 * Function: stringToHEX
 * Purpose: Convert string to base 16 HEX characters
 */
void stringToHEX(string &str) {
    auto i = 0;
    unsigned int c;
    istringstream char_stream(str);
    while (char_stream >> hex >> c) {
        key[i] = c;
        i++;
    }
}

/*
 * Function: divisibleBy16
 * Purpose: Take modulus of file size, if file size is
 *          evenly divisible by 16 return true else false
 */
bool divisibleBy16(int file_size) {
    if (file_size % 16 == 0)    // If file size is not evenly divisible by 16
        return true; // (16 - (file_size % 16));   // Padding will be the remainder

    return false;
}

/*
 * Function: fileExists
 * Purpose: Check if file path exists
 */
bool fileExists(const string &source_file_path) {
    ifstream source_file;   // Input file stream
    source_file.open(source_file_path);    // Attempt to open file in binary mode
    if (source_file.fail()) {  // If file fails to open (or doe not exist) end program
        cout << "Enter a valid path";
        return false;
    } else {   // The file was successfully opened
        source_file.close();
        return true;
    }
}

/*
 * Function: getKeyFromUser
 * Purpose: Receive and sanitize user input
 */
void getKeyFromUser() {
    string user_input;
    string temp_input;
    int key_size = 32;

    cout << "\n\n[*] Enter key:";
    getline(cin, user_input);    // Get key from command line
    stringToLowerCase(user_input);  // Convert string to lower case
    temp_input = user_input;
    stripWhiteSpace(user_input);    // Remove white space

    if (!isHexDigit(user_input)) {    // If user input is not HEX digits exit
        cout << "Input must be base 16 HEX";
        exit(EXIT_FAILURE);
    }
    if (user_input.size() != key_size) { // If the key size is not equal to 32 hex digits
        cout << "Key must be 32 HEX digits" << endl;
        exit(EXIT_FAILURE);
    }
    stringToHEX(temp_input);
};

/*
 * Function: appendExtension
 * Purpose: Remove extension from source file and append .enc
 *          extension for encrypted file output
 */
string appendExtension(string &source_file_path) {
    string destination_file_path;
    // Remove extension from source file example .txt,.jpg,.pdf etc...
    destination_file_path = source_file_path.substr(0, source_file_path.find('.', 0));
    destination_file_path = destination_file_path + ".enc"; // Append .enc extension to file
    return destination_file_path;
}

void filePathError() {
    cout << "Usage: Provide the absolute path of file Example: AES128Encrypt /AbsolutePath/FileToEncrypt.txt: ";
}

void banner() {
    cout << "\n###################### AES 128-bit Encryption ######################" << endl;
    cout << "[-] Example usage: AES128Encrypt file_to_be_encrypted.txt" << endl;
    cout << "[-] Enter 32 digit HEX key i.e. f7 dd 3b 98 1e f3 25 c3 e3 51 09 d2 6b 5c aa dd";
}

int main(int argc, char **argv) {

    int padded_file_length = 0;
    int file_size = 0;
    int padding = 0;
    unsigned char hex_values[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                                  0x0f, 0x10};
    unsigned char expandedKey[176];
    char *temp = nullptr;
    string destination_file_path;
    ifstream source_file;
    ofstream destination_file;

    banner();

    if (argc == 2) {

        string source_file_path(argv[1]);   // Store absolute file path

        if (!fileExists(source_file_path))
            return 0;

        file_size = getFileSize(source_file_path);

        source_file.open(source_file_path, ios::binary | ios::in);
        temp = new char[file_size];
        source_file.read(temp, file_size);    // Read text from file to temp array
        destination_file_path = appendExtension(source_file_path);
        destination_file.open(destination_file_path,
                              ios::binary | ios::out); // Pass absolute file path for encrypted file with .enc extension

    } else {
        filePathError();
    }

    getKeyFromUser();   // Takes HEX key from command line

    if (divisibleBy16(file_size)) { // If file size is divisible by 16  add another 16 bytes as PKCS5 padding
        padded_file_length = file_size + 16;
    } else {  // Else size of the file in bytes is not divisible by 16
        padding = (16 - (file_size % 16));
        padded_file_length = file_size + padding;   // Create new array with size divisible by 16
    }

    keySchedule(key, expandedKey);

    auto *padded_file = new unsigned char[padded_file_length];   // Copy original message to padded message

    for (int num_bytes = 0; num_bytes < padded_file_length; num_bytes++) {
        if (num_bytes == file_size) {   // If number of bytes equals file size
            if (padding == 0) {   // If file size is divisible by 16
                padding = 16;   // Append 16 bytes of padding to end of file
                for (int i = file_size; i < file_size + padding; i++) {
                    padded_file[i] = (int) hex_values[padding - 1];  // Index 15
                }
            } else {
                for (int i = file_size; i < padded_file_length; i++) {
                    padded_file[i] = (int) hex_values[padding - 1];
                }
            }
            break;
        } else
            padded_file[num_bytes] = temp[num_bytes];
    }

    for (int bytes = 0; bytes < padded_file_length; bytes += BUFFERSIZE) {
        AES128Encrypt(padded_file + bytes, key, expandedKey);
    }

    for (int i = 0; i < padded_file_length; i++) {
        destination_file << padded_file[i];
    }

    source_file.close();
    destination_file.close();

    return 0;
}
