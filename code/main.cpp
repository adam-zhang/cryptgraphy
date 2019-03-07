#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <iterator>
#include <mbedtls/aes.h>
#include <stdio.h>
#include <cassert>
#include <memory>
#include "Cryptographer.h"

using namespace std;

typedef std::basic_string<unsigned char> ustring;
const size_t SIZE = 16;

ustring gather(const ustring& text)
{
	size_t count = text.size() % SIZE;
	size_t length = 16 - count;
	ustring u = text;
	for(size_t i = 0; i != length; ++i)
	{
		unsigned char c = 0;
		u.push_back(c);
	}
	assert(u.size() % 16 == 0);
	return u;
}


vector<ustring> seperate(const ustring& text)
{
	vector<ustring> v;
	auto length = text.size() / 16;
	for(auto i = text.begin(); i != text.end(); i += SIZE)
	{
		ustring s;
		copy(i,  i + SIZE, back_inserter(s));
		v.push_back(s);
	}
	return v;
}

vector<ustring> split(const ustring& text)
{
	ustring u = text;
	if (text.size() % SIZE != 0)
		u = gather(u);
	return seperate(u);	
}

//ustring encrypt(const vector<unsigned char>& text, const array<unsigned char, 16>& key)
//{
//	assert(text.size() % SIZE == 0);
//	mbedtls_aes_context context;
//	mbedtls_aes_init(&context);
//	assert(key.size() == 16);
//	int ret = mbedtls_aes_setkey_enc(&context, &key[0], SIZE * 8);
//
//	ustring r;
//	for(auto i = 0; i != text.size(); i += SIZE)
//	{
//		vector<unsigned char> buffer(16);
//		mbedtls_aes_crypt_ecb(&context, MBEDTLS_AES_ENCRYPT, , &buffer[0]);
//		copy(buffer.begin(), buffer.end(), back_inserter(r));
//	}
//	mbedtls_aes_free(&context);
//	return r;
//}

ustring decrypt(const ustring& text, const array<unsigned char, SIZE>& key)
{
	auto v = split(text);
	mbedtls_aes_context context;
	mbedtls_aes_init(&context);
	mbedtls_aes_setkey_dec(&context, &key[0], key.size() * 8);
	ustring r;
	for(auto s : v)
	{
		vector<unsigned char> buffer(16);
		mbedtls_aes_crypt_ecb(&context, MBEDTLS_AES_ENCRYPT, s.c_str(), &buffer[0]);
		copy(buffer.begin(), buffer.end(), back_inserter(r));
	}
	return r;
}

//ustring toUstring(const string& s)
//{
//	ustring r;
//	copy(s.begin(), s.end(), back_inserter(r));
//	return r;
//}
//
//ustring toUstring(const unsigned char* text, size_t size)
//{
//	ustring r;
//	for(size_t i = 0; i != size; ++i)
//		r.push_back(text[i]);
//	return r;
//}
//
string toString(const ustring& s)
{
	string r;
	copy(s.begin(), s.end(), back_inserter(r));
	return r;
}


int main(int argc, char *argv[])
{
	//mbedtls_aes_context aes_ctx;
	//密钥数值
	unsigned char key[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x00};

	//明文空间
	vector<unsigned char> plain; 
       	unsigned char s[] = "01234568901234567890123456789";
	copy(begin(s), end(s), back_inserter(plain));
	//解密后明文的空间
	//unsigned char dec_plain[16]={0};
	//密文空间
	//unsigned char cipher[16]={0};

	//mbedtls_aes_init( &aes_ctx );


	////设置加密密钥
	//mbedtls_aes_setkey_enc( &aes_ctx, &key[0], 128);

	//printf("\n*********** before:%s\n", plain);
	//mbedtls_aes_crypt_ecb( &aes_ctx, MBEDTLS_AES_ENCRYPT, plain, cipher );
	//printf("\n*********** after:%s\n", cipher);
	////设置解密密钥
	//mbedtls_aes_setkey_dec(&aes_ctx, &key[0], 128);

	//mbedtls_aes_crypt_ecb( &aes_ctx, MBEDTLS_AES_DECRYPT, cipher, dec_plain );
	//printf("\n*********** after:%s\n", dec_plain);
	vector<unsigned char> keyPackage;
	copy(begin(key), end(key), back_inserter(keyPackage));
	cout << "1 keyLength:" << keyPackage.size() << endl;

	unique_ptr<Cryptographer> aes = make_unique<AesCryptographer>();
	//unsigned char encrypted[32] = {0};
       	auto encrypted = aes->encrypt(plain, keyPackage);

	//for(int i = 0; i < 16; ++i)
	//{
	//	assert(cipher[i] == encrypted[i]);
	//}

	//unsigned char decrypted[33] = {0};
	auto origin = aes->decrypt(encrypted, keyPackage);
	//for(int i = 0; i < 16; ++i)
	//{
	//	assert(decrypted[i] == dec_plain[i]);
	//}
	printf("after:%s\n", &origin[0]);

	//mbedtls_aes_free( &aes_ctx );
	//string sample = "123456789012345678901234567890";
	//ustring text;
	//copy(begin(sample), end(sample), back_inserter(text));
	//auto encrypted = encrypt(plain, key);
	//for (int i = 0; i != 16; ++i)
	//{
	//	assert(cipher[i] == encrypted[i]);
	//}
	//auto r = decrypt(encrypted, key);
	//cout << toString(r) << endl;
	cin.get();
	return 0;
}

