#include "Cryptographer.h"
#include <cassert>
#include <iostream>
#include <iterator>
#include <vector>
#include <algorithm>
#include <mbedtls/aes.h>

using namespace std;

Cryptographer::Cryptographer()
{
}

Cryptographer::~Cryptographer()
{
}


bool AesCryptographer::encrypt(unsigned char* text, size_t textLength, unsigned char* key, size_t keyLength, unsigned char* output, size_t outputLength)
{
	cout << "keyLength:" << keyLength << endl;
	assert(textLength % AesCryptographer::SIZE == 0);
	assert(keyLength == 16);
	if (textLength != outputLength)
		return false;
	mbedtls_aes_context context;
	mbedtls_aes_init(&context);
	mbedtls_aes_setkey_enc(&context, key, keyLength * 8);
	for(size_t i = 0; i != textLength; i += AesCryptographer::SIZE)
	{
		vector<unsigned char> buffer(16);
		mbedtls_aes_crypt_ecb(&context, MBEDTLS_AES_ENCRYPT, &text[i], &buffer[0]);
		copy_n(buffer.begin(), SIZE, &output[i]);
	}
	mbedtls_aes_free(&context);
	return true;
}

bool AesCryptographer::decrypt(unsigned char* text, size_t textLength, unsigned char* key, size_t keyLength, unsigned char* output, size_t outputLength)
{
	assert(textLength % AesCryptographer::SIZE == 0);
	assert(keyLength == 16);
	if (textLength != outputLength)
		return false;
	mbedtls_aes_context context;
	mbedtls_aes_init(&context);
	mbedtls_aes_setkey_dec(&context, key, keyLength * 8);
	for(size_t i = 0; i != textLength; i += AesCryptographer::SIZE)
	{
		vector<unsigned char> buffer(16);
		mbedtls_aes_crypt_ecb(&context, MBEDTLS_AES_DECRYPT, &text[i], &buffer[0]);
		copy_n(buffer.begin(), SIZE, &output[i]);
	}
	mbedtls_aes_free(&context);
	return true;
}


vector<unsigned char> AesCryptographer::encrypt(const vector<unsigned char>& text, const vector<unsigned char>& key)
{
	auto input = text;
	auto keyInput = key;
	fill_n(back_inserter(input),(text.size() % SIZE) ? SIZE - text.size() % SIZE : 0 , '\0');
	fill_n(back_inserter(keyInput), (keyInput.size() % SIZE) ? SIZE - text.size() % SIZE : 0, '\0');
	vector<unsigned char> buffer(input.size());
	encrypt(&input[0], input.size(), &keyInput[0], keyInput.size(), &buffer[0], buffer.size());
	return buffer;
}

vector<unsigned char> AesCryptographer::decrypt(const vector<unsigned char>& text, const vector<unsigned char>& key)
{
	auto input = text;
	auto keyInput = key;
	fill_n(back_inserter(input), text.size() % SIZE ? SIZE - text.size() % SIZE : 0 , '\0');
	fill_n(back_inserter(keyInput), text.size() % SIZE ? SIZE - text.size() % SIZE : 0, '\0');
	vector<unsigned char> buffer(input.size());
	decrypt(&input[0], input.size(), &keyInput[0], keyInput.size(), &buffer[0], buffer.size());
	return buffer;
}
