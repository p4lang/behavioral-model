crypto_SOURCES = crypto.cpp
crypto_LDADD = -lcrypto

CPPFLAGS += -I../../ -fPIC -shared

libexterncrypto.so : $(crypto_SOURCES)
	g++ $(CPPFLAGS) $(crypto_SOURCES) -o libexterncrypto.so $(crypto_LDADD)

clean:
	rm -rf libexterncrypto.so

