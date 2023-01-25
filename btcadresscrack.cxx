#include "wordlist.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"

#include <iostream>

const char* knownwords[2] = {"hollow", "blast"};
using namespace CryptoPP;

const char* targetHEX = "0x272063C80EBB47CFA3F4CC088187F4B15CE05F7E917BBE7830785B6B16F3CF";
const char* targetB58 = "bc1q7kw2uepv6hfffhhxx2vplkkpcwsslcw9hsupc6";

int main(){

    // test private key from mnemonic
    std::string someseed = "hollow blast abandon ability able about above absent absorb abstract absurd absurd";
    byte password[] ="punch shock entire north file identify";
    size_t plen = strlen((const char*)password);

    byte salt[] = "mnemonic";
    size_t slen = strlen((const char*)salt);

    byte derived[SHA512::DIGESTSIZE];
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    byte unused = 0;
    pbkdf.DeriveKey(derived, sizeof(derived), unused, password, plen, salt, slen, 2048, 0.0f);  
    std::string resultx;
    HexEncoder encoder(new StringSink(resultx));

    encoder.Put(derived, sizeof(derived));
    encoder.MessageEnd();

    std::cout << "Derived: " << resultx << std::endl << std::hex << derived << std::endl;

    ECDSA<ECP, SHA256>::PrivateKey privKey;
    //privKey.Initialize( derived, ASN1::secp256k1() );


    // test private key initialization
    AutoSeededRandomPool prng;
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    privateKey.Initialize( prng, ASN1::secp256k1() );
    bool result = privateKey.Validate( prng, 3 );
    std::cout << result << "\n";
    const Integer& x = privateKey.GetPrivateExponent();
    std::cout << std::hex << x << "\n";

    // test elliptic curve sk->pk
    ECDSA<ECP, SHA256>::PrivateKey privateKey2;
    ECDSA<ECP, SHA256>::PublicKey publicKey2;
    const Integer x2(0x1995);       // private exponent
    std::cout << "setting x2\n";
    privateKey2.Initialize( ASN1::secp256k1(), x2 );
    privateKey2.MakePublicKey( publicKey2 );
    std::cout << "debug\n";
    std::cout << publicKey2.GetPublicElement().x << "\n" << publicKey2.GetPublicElement().y << "\n";
    return 0;
}
