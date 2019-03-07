#ifndef __CRYPTOGRAPHER__H
#define __CRYPTOGRAPHER__H

#include <string>
#include <vector>
//typedef std::basic_string<unsigned char> std::vector<unsigned char>;

class Cryptographer
{
	public:
		Cryptographer();
		~Cryptographer();
	public:
		//virtual bool encrypt(unsigned char* text, size_t textLength, unsigned char* key, size_t keyLength, unsigned char* output, size_t outputLength) = 0;
		//virtual bool decrypt(unsigned char* text, size_t textLength, unsigned char* key, size_t keyLength, unsigned char* output, size_t outputLength) = 0;
		virtual std::vector<unsigned char> encrypt(const std::vector<unsigned char>& text, const std::vector<unsigned char>& key) = 0;
		virtual std::vector<unsigned char> decrypt(const std::vector<unsigned char>& text, const std::vector<unsigned char>& key) = 0;
};

class AesCryptographer : public Cryptographer
{
	private:
		bool encrypt(unsigned char* text, size_t textLength, unsigned char* key, size_t keyLength, unsigned char* output, size_t outputLength);
		bool decrypt(unsigned char* text, size_t textLength, unsigned char* key, size_t keyLength, unsigned char* output, size_t outputLength);
	public:
		virtual std::vector<unsigned char> encrypt(const std::vector<unsigned char>& text, const std::vector<unsigned char>& key);
		virtual std::vector<unsigned char> decrypt(const std::vector<unsigned char>& text, const std::vector<unsigned char>& key);
	private:
		enum
		{
			SIZE = 16,
		};
};
#endif//__CRYPTOGRAPHER__H
