#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+----------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(IV|C) (32 bytes for SHA256) |
 * +------------+--------------------+----------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */

	// buffers to hold values
	unsigned char* hmac;
	unsigned char* aes;
	
	hmac = malloc(32);
	aes = malloc(32);

	if(entropy != NULL)
	{
		// generate hmac and aes
		HMAC(EVP_sha512(), KDF_KEY, 32, entropy, entLen, hmac, NULL);
		HMAC(EVP_sha512(), KDF_KEY, 32, 0, 0, aes, NULL);

		// save hmac and aes
		for(int i=0; i<32; i++)
		{
			K->hmacKey[i] = hmac[i];
			K->aesKey[i] = aes[i];
		}

		// free buffers
		free(hmac);
		free(aes);
	}
	else
	{
		// generate hmac and aes
		randBytes(hmac, 32);
		randBytes(aes, 32);

		// save hmac and aes
		for(int i=0; i<32; i++)
		{
			K->hmacKey[i] = hmac[i];
			K->aesKey[i] = aes[i];
		}

		// free buffers
		free(hmac);
		free(aes);
	}

	return 0;
}
size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}
size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len, SKE_KEY* K, unsigned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */

	if(IV == NULL)
	{
		IV = malloc(16);
		memcpy(IV,inBuf,len);

	}
	
	memcpy(outBuf, IV,16);
	EVP_CIPHER_CTX* cipher = EVP_CIPHER_CTX_new();

	int out;
	int ret = EVP_EncrpytUpdate(ctx, outBuf +16, &out, inBuf, len);
	if(ret != 1)
	{
		fprintf(stderr, "Error when executing EVP_EncryptUpdate")
		//ERR_print_errors_fp(stderr);
	}
	
	EVP_CIPHER_CTX_Free(cipher); 
	
	return 0; /* TODO: should return number of bytes written, which
	             hopefully matches ske_getOutputLen(...). */
}
size_t ske_encrypt_file(const char* fnout, const char* fnin, SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */
	return 0;
}
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len, SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */
	return 0;
}
size_t ske_decrypt_file(const char* fnout, const char* fnin, SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */
	return 0;
}
