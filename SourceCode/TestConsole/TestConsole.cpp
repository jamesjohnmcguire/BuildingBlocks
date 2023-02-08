#include <iostream>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <openssl/opensslv.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#ifdef CONFIG_ECC
#include <openssl/ec.h>
#include <openssl/x509.h>
#endif /* CONFIG_ECC */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#else /* OpenSSL version >= 3.0 */
#include <openssl/cmac.h>
#endif /* OpenSSL version >= 3.0 */

int main()
{
	std::cout << "Hello World!\n";

	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* gctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	gctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

	if (gctx)
	{
		int var1 = EVP_PKEY_keygen_init(gctx);
		int var3 = EVP_PKEY_generate(gctx, &pkey);

		if (pkey != nullptr)
		{
			EVP_PKEY_free(pkey);
			pkey = NULL;

		}
		EVP_PKEY_CTX_free(gctx);
		std::cout << "Wrapping Up\n";
	}

	return 0;
}
