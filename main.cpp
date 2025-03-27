#include <iostream>
#include <bitset>
#include <string>
using namespace std;


int IP[8] = {1, 5, 2, 0, 3, 7, 4, 6};
int IP_1[8] = {3, 0, 2, 4, 6, 1, 7, 5};
int EP[8] = {3, 0, 1, 2, 1, 2, 3, 0};
int P4[4] = {1, 3, 2, 0};
int P10[10] = {2, 4, 1, 6, 3, 9, 0, 8, 7, 5};
int P8[8] = {5, 2, 6, 3, 7, 4, 9, 8};

int S0[4][4] = {{1, 0, 3, 2}, {3, 2, 1, 0}, {0, 2, 1, 3}, {3, 1, 0, 2}};
int S1[4][4] = {{0, 1, 2, 3}, {2, 0, 1, 3}, {3, 0, 1, 0}, {2, 1, 0, 3}};

bitset<10> permute10(bitset<10> input, int* table) {
    bitset<10> output;
    for (int i = 0; i < 10; i++) {
        output[i] = input[table[i]];
    }
    return output;
}

bitset<8> permute8(bitset<8> input, int* table) {
    bitset<8> output;
    for (int i = 0; i < 8; i++) {
        output[i] = input[table[i]];
    }
    return output;
}


void generateKeys(bitset<10> key, bitset<8>& K1, bitset<8>& K2) {
    key = permute10(key, P10);
    bitset<5> left = (key.to_ulong() >> 5) & 0b11111;
    bitset<5> right = key.to_ulong() & 0b11111;
    left = (left << 1) | (left >> 4);
    right = (right << 1) | (right >> 4);
    K1 = permute8(bitset<8>((left.to_ulong() << 5) | right.to_ulong()), P8);
    left = (left << 2) | (left >> 3);
    right = (right << 2) | (right >> 3);
    K2 = permute8(bitset<8>((left.to_ulong() << 5) | right.to_ulong()), P8);
}

bitset<4> functionF(bitset<4> R, bitset<8> K) {
    bitset<8> expanded = permute8(bitset<8>(R.to_ulong()), EP);
    expanded ^= K;
    int row = (expanded[0] << 1) | expanded[3];
    int col = (expanded[1] << 1) | expanded[2];
    bitset<2> left(S0[row][col]);
    row = (expanded[4] << 1) | expanded[7];
    col = (expanded[5] << 1) | expanded[6];
    bitset<2> right(S1[row][col]);
    return bitset<4>((left.to_ulong() << 2) | right.to_ulong());
}

bitset<8> sdesEncrypt(bitset<8> plaintext, bitset<10> key) {
    bitset<8> permuted = permute8(plaintext, IP);
    bitset<4> L = (permuted.to_ulong() >> 4) & 0b1111;
    bitset<4> R = permuted.to_ulong() & 0b1111;
    bitset<8> K1, K2;
    generateKeys(key, K1, K2);
    L ^= functionF(R, K1);
    swap(L, R);
    L ^= functionF(R, K2);
    return permute8(bitset<8>((L.to_ulong() << 4) | R.to_ulong()), IP_1);
}

bitset<8> sdesDecrypt(bitset<8> ciphertext, bitset<10> key) {
    bitset<8> permuted = permute8(ciphertext, IP);
    bitset<4> L = (permuted.to_ulong() >> 4) & 0b1111;
    bitset<4> R = permuted.to_ulong() & 0b1111;
    bitset<8> K1, K2;
    generateKeys(key, K1, K2);
    L ^= functionF(R, K2);
    swap(L, R);
    L ^= functionF(R, K1);
    return permute8(bitset<8>((L.to_ulong() << 4) | R.to_ulong()), IP_1);
}

string encryptText(string text, bitset<10> key) {
    string encrypted = "";
    for (char c : text) {
        bitset<8> encryptedChar = sdesEncrypt(bitset<8>(c), key);
        encrypted += (char)encryptedChar.to_ulong();
    }
    return encrypted;
}

string toBinaryString(string text) {
    string binary = "";
    for (char c : text) {
        binary += bitset<8>(c).to_string() + " ";
    }
    return binary;
}

string decryptText(string text, bitset<10> key) {
    string decrypted = "";
    for (char c : text) {
        bitset<8> decryptedChar = sdesDecrypt(bitset<8>(c), key);
        decrypted += (char)decryptedChar.to_ulong();
    }
    return decrypted;
}

int main() {
    string plaintext = "Example of work";
    bitset<10> key("1010000010");
    string ciphertext = encryptText(plaintext, key);
    string plaintextBinary = toBinaryString(plaintext);
    string decryptedText = decryptText(ciphertext, key);
    string decryptedBinary = toBinaryString(decryptedText);

    cout << "Відкритий текст: " << plaintext << endl;
    cout << "Відкритий текст (двійковий код): " << plaintextBinary << endl;
    cout << "Зашифрований текст (двійковий код): " << ciphertext << endl;
    cout << "Розшифрований текст (двійковий код): " << decryptedBinary << endl;
    cout << "Розшифрований текст: " << decryptedText << endl;
    return 0;
}