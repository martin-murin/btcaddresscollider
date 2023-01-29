#include "wordlist.h"
#include "segwit_addr.h"
#include "base58.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/sha.h"
#include "cryptopp/ripemd.h"
#include "cryptopp/hex.h"

#include <iostream>

const char* knownwords[2] = {"hollow", "blast"};
using namespace CryptoPP;

const char* targetHEX = "0x272063C80EBB47CFA3F4CC088187F4B15CE05F7E917BBE7830785B6B16F3CF";
const char* targetB58 = "bc1q7kw2uepv6hfffhhxx2vplkkpcwsslcw9hsupc6";


void byteToStr(const byte inputByteArr[], int size, std::string & outputStr){
    ArraySource strsrc(inputByteArr, size, true,
        new HexEncoder(
            new StringSink(outputStr)
        )
    );
}

template <unsigned int SIZE> std::string byteToStr(const byte (& inputByteArr)[SIZE]){
    std::string outputStr;
    ArraySource strsrc(inputByteArr, sizeof(inputByteArr), true,
        new HexEncoder(
            new StringSink(outputStr)
        )
    );
    return outputStr;
}

template <unsigned int SIZE> void strToByte(const std::string inputStr, byte (& outputByteArr)[SIZE], int size){
    StringSource strsrc(inputStr, true,
        new HexDecoder(
            new ArraySink(outputByteArr, size)
        )
    );
}

void check_output_byte(const byte arr[], int size){
    std::string root_str;
    byteToStr(arr, size, root_str);
    std::cout << root_str << std::endl;
}

template <unsigned int MNEMSIZE, unsigned int SALTSIZE> void deriveSeedFromMnemonic(const byte (& mnemonicSentence)[MNEMSIZE], const byte (& salt)[SALTSIZE], byte (& derivedSeed)[SHA512::DIGESTSIZE]){
    // Password Based Key Derivation Function
    PKCS5_PBKDF2_HMAC<SHA512> hashPBKDF2;
    size_t mnem_size = strlen((const char*) mnemonicSentence);
    size_t salt_size = strlen((const char*) salt);
    size_t seed_size = sizeof(derivedSeed);
    hashPBKDF2.DeriveKey(derivedSeed, seed_size, 0x00, mnemonicSentence, mnem_size, salt, salt_size, 2048, 0.0f);
}

void deriveMasterKeyFromSeed(const byte (& seed)[SHA512::DIGESTSIZE], byte (& masterPrivKey)[32], byte (& masterChainCode)[32]){
    byte salt[] = "Bitcoin seed";
    unsigned int salt_size = sizeof(salt);

    byte hashresult[SHA512::DIGESTSIZE];
    HMAC< SHA512 > hmacSHA512(salt, salt_size);
    ArraySource arrsrc(seed, sizeof(seed), true,
        new HashFilter(hmacSHA512,
            new ArraySink(hashresult, SHA512::DIGESTSIZE)
        )
    );

    // Split hash result into private key (left 32 bytes) and chain code (right 32 bytes)
    memcpy(&masterPrivKey, &hashresult, 32);
    memcpy(&masterChainCode, &(hashresult[32]), 32);
}

void generatePubKeyFromPrivKey(const byte (& privKey)[32], byte (& pubKey)[33]){
    ECDSA<ECP, SHA256>::PrivateKey privateKeyECDSA;
    privateKeyECDSA.Initialize(ASN1::secp256k1(), Integer(privKey, sizeof(privKey)));

    ECDSA<ECP, SHA256>::PublicKey publicKeyECDSA;
    privateKeyECDSA.MakePublicKey(publicKeyECDSA);
    publicKeyECDSA.AccessGroupParameters().SetPointCompression(true);

    // Public key compression
    byte pubKeyElementX[32];
    byte pubKeyElementY[32];
    publicKeyECDSA.GetPublicElement().x.Encode(pubKeyElementX, sizeof(pubKeyElementX));
    publicKeyECDSA.GetPublicElement().y.Encode(pubKeyElementY, sizeof(pubKeyElementY));

    if(publicKeyECDSA.GetPublicElement().y.IsEven()){
        pubKey[0] = 0x02;
    }
    else{
        pubKey[0] = 0x03;
    }
    memcpy(&(pubKey[1]), &pubKeyElementX, 32);
}

void deriveHardChildPrivKey(const byte (& masterPrivKey)[32], const byte (& masterChainCode)[32], unsigned int index, byte (& childPrivKey)[32], byte (& childChainCode)[32]){
    byte hashinput[1+sizeof(masterPrivKey)+sizeof(unsigned int)];
    byte hashresult[SHA512::DIGESTSIZE];
    byte index_byte[sizeof(unsigned int)];
    memcpy(index_byte, &index, sizeof(unsigned int));
    std::reverse(index_byte, index_byte+sizeof(unsigned int));
    hashinput[0] = 0x00;
    memcpy(&(hashinput[1]), &masterPrivKey, sizeof(masterPrivKey));
    memcpy(&(hashinput[1+sizeof(masterPrivKey)]), &index_byte, sizeof(unsigned int));
    HMAC< SHA512 > hmacSHA512(masterChainCode, sizeof(masterChainCode));
    ArraySource arrsrc(hashinput, sizeof(hashinput), true,
        new HashFilter(hmacSHA512, 
            new ArraySink(hashresult, SHA512::DIGESTSIZE)
        )
    );
    Integer childPrivKey_int((Integer(hashresult, 32) + Integer(masterPrivKey, 32)) % Integer("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141h"));
    childPrivKey_int.Encode(childPrivKey, 32);
    memcpy(&childChainCode, &(hashresult[32]), 32);
}

void deriveSoftChildPrivKey(const byte (& masterPrivKey)[32], const byte (& masterPubKey)[33], const byte (& masterChainCode)[32], unsigned int index, byte (& childPrivKey)[32], byte (& childChainCode)[32]){
    byte hashinput[sizeof(masterPubKey)+sizeof(unsigned int)];
    byte hashresult[SHA512::DIGESTSIZE];
    byte index_byte[sizeof(unsigned int)];

    memcpy(index_byte, &index, sizeof(unsigned int));
    std::reverse(index_byte, index_byte+sizeof(unsigned int));

    memcpy(&hashinput, &masterPubKey, sizeof(masterPubKey));
    memcpy(&(hashinput[sizeof(masterPubKey)]), &index_byte, sizeof(unsigned int));
    
    HMAC< SHA512 > hmacSHA512(masterChainCode, sizeof(masterChainCode));
    ArraySource arrsrc(hashinput, sizeof(hashinput), true,
        new HashFilter(hmacSHA512, 
            new ArraySink(hashresult, SHA512::DIGESTSIZE)
        )
    );
    Integer childPrivKey_int((Integer(hashresult, 32) + Integer(masterPrivKey, 32)) % Integer("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141h"));
    childPrivKey_int.Encode(childPrivKey, 32);
    memcpy(&childChainCode, &(hashresult[32]), 32);
}

void hash160(const byte (& publicKey)[33], byte (& hashedPubKey)[RIPEMD160::DIGESTSIZE]){
    // ripemd160(sha256(publicKey))
    SHA256 hashSHA256;
    RIPEMD160 hashRIPEMD160;

    ArraySource arrsrc(publicKey, sizeof(publicKey), true,
        new HashFilter(hashSHA256,
            new HashFilter(hashRIPEMD160,
                new ArraySink(hashedPubKey, RIPEMD160::DIGESTSIZE)
            )
        )
    );
}

void serializationPrefix(char* version, byte depth, const byte (& parentPublicKey)[33], unsigned int childNumber, byte (& serialPrefix)[13]){
    // Version bytes of the key ("zprv" and "zpub" in BIP 84 derivation path)
    byte ver[4];
    if(strcmp(version, "zprv") == 0){ver[0] = 0x04; ver[1] = 0xb2; ver[2] = 0x43; ver[3] = 0x0c;}
    else if(strcmp(version, "zpub")){ver[0] = 0x04; ver[1] = 0xb2; ver[2] = 0x47; ver[3] = 0x46;}
    else if(strcmp(version, "yprv")){ver[0] = 0x04; ver[1] = 0x9d; ver[2] = 0x78; ver[3] = 0x78;}
    else if(strcmp(version, "ypub")){ver[0] = 0x04; ver[1] = 0x9d; ver[2] = 0x7c; ver[3] = 0xb2;}
    else if(strcmp(version, "xprv")){ver[0] = 0x04; ver[1] = 0x88; ver[2] = 0xad; ver[3] = 0xe4;}
    else if(strcmp(version, "xpub")){ver[0] = 0x04; ver[1] = 0x88; ver[2] = 0xb2; ver[3] = 0x1e;}
    else{ver[0] = 0x00; ver[1] = 0x00; ver[2] = 0x00; ver[3] = 0x00;}
    
    // Convert child number into byte array
    byte childN[sizeof(unsigned int)];
    memcpy(childN, &childNumber, sizeof(unsigned int));
    std::reverse(childN, childN+sizeof(unsigned int));

    // Parent fingerprint is HASH160 of the public key
    byte parentFingerprint[RIPEMD160::DIGESTSIZE];
    hash160(parentPublicKey, parentFingerprint);

    // Write serialization prefix
    memcpy(&serialPrefix, &ver, 4);
    serialPrefix[4] = depth;
    memcpy(&(serialPrefix[5]), parentFingerprint, 4);
    memcpy(&(serialPrefix[9]), childN, sizeof(unsigned int));
}

template <unsigned int KEYSIZE> void serializeKey(const byte (& prefix)[13], const byte (& key)[KEYSIZE], const byte (& chain)[32], byte (& serializedKey)[82], std::string & serializedKey_str){
    // Prepare byte sequence for SHA256 hash
    byte tempSequence[78];
    memcpy(&tempSequence, &prefix, sizeof(prefix));
    memcpy(&(tempSequence[sizeof(prefix)]), &chain, sizeof(chain));
    tempSequence[sizeof(prefix)+sizeof(chain)] = 0x00;
    memcpy(&(tempSequence[sizeof(tempSequence)-sizeof(key)]), key, sizeof(key));

    // Obtain checksum using SHA256
    SHA256 hashSHA256;
    byte checksum[SHA256::DIGESTSIZE];
    ArraySource arrsrc(tempSequence, sizeof(tempSequence), true,
        new HashFilter(hashSHA256,
            new HashFilter(hashSHA256,
                new ArraySink(checksum, SHA256::DIGESTSIZE)
            )
        )
    );

    // Write serialized key and checksum 
    memcpy(&serializedKey, &tempSequence, 78);
    memcpy(&(serializedKey[78]), &checksum, 4);
    
    // Convert to base58
    std::vector<uint8_t> serializedKey_uint8(&serializedKey[0], &serializedKey[sizeof(serializedKey)]);
    serializedKey_str = EncodeBase58(serializedKey_uint8, base58map);
}

std::string getAddressP2WPKH(const byte (& publicKey)[33]){
    // Pay-To-Witness-Public-Key-Hash Address (native segwit)
    byte hashedPubKey[RIPEMD160::DIGESTSIZE];
    hash160(publicKey, hashedPubKey);

    // Encode with BECH32
    std::string hrp = "bc";         // human readable part
    int witver = 0;                 // witness version
    std::vector<uint8_t> witprog(&hashedPubKey[0], &hashedPubKey[RIPEMD160::DIGESTSIZE]);
    std::string address_p2wpkh = segwit_addr::encode(hrp, witver, witprog);
    return address_p2wpkh;

}


int main(){
    // Prepare mnemonic sentence and passphrase
    byte mnemonicSentence[] = "tip unfair advance patient action teach behind dawn street uphold arrest error";
    byte mnemBase[] = "mnemonic";
    byte mnemPassphrase[] = "";

    byte mnemonicSalt[sizeof(mnemBase)+sizeof(mnemPassphrase)-1];
    memcpy(&mnemonicSalt, &mnemBase, sizeof(mnemBase));
    memcpy(&(mnemonicSalt[sizeof(mnemBase)-1]), &mnemPassphrase, sizeof(mnemPassphrase));

    // Generate seed, private/public key pair, chain code and prefixes
    byte master_seed[SHA512::DIGESTSIZE];
    byte master_privKey[32];
    byte master_pubKey[33];
    byte master_chainCode[32];
    byte master_privPrefix[13];
    byte master_pubPrefix[13];

    deriveSeedFromMnemonic(mnemonicSentence, mnemonicSalt, master_seed);
    //deriveSeedFromMnemonic(mnemonicSentence, sizeof(mnemonicSentence), mnemonicSalt, sizeof(mnemonicSalt), master_seed);
    deriveMasterKeyFromSeed(master_seed, master_privKey, master_chainCode);
    generatePubKeyFromPrivKey(master_privKey, master_pubKey);
    serializationPrefix(const_cast<char*>("zprv"), 0x00, master_pubKey, 0, master_privPrefix);
    serializationPrefix(const_cast<char*>("zpub"), 0x00, master_pubKey, 0, master_pubPrefix);

    // Print
    std::cout << "======== MASTER KEY ========" << std::endl;
    std::cout << "Mnemonic sentence (human readable):    " << reinterpret_cast<const char*>(mnemonicSentence) << std::endl;
    std::cout << "Mnemonic SALT (human readable):        " << reinterpret_cast<const char*>(mnemonicSalt) << std::endl;
    std::cout << "Mnemonic sentence:                     " << byteToStr(mnemonicSentence) << std::endl;
    std::cout << "Mnemonic base:                         " << byteToStr(mnemBase) << std::endl;
    std::cout << "Passphrase:                            " << byteToStr(mnemPassphrase) << std::endl;
    std::cout << "Mnemonic SALT:                         " << byteToStr(mnemonicSalt) << std::endl;
    std::cout << "SEED:                                  " << byteToStr(master_seed) << std::endl;
    std::cout << "MASTER PRIVATE KEY:                    " << byteToStr(master_privKey) << std::endl;
    std::cout << "MASTER PUBLIC KEY:                     " << byteToStr(master_pubKey) << std::endl;
    std::cout << "Master chain code:                     " << byteToStr(master_chainCode) << std::endl;
    std::cout << std::endl;


    // BIP 84 derivation path m/84'/0'/0'/0/0
    byte child_84_privKey[32];
    byte child_84_pubKey[33];
    byte child_84_chainCode[32];
    byte child_84_privPrefix[13];
    byte child_84_pubPrefix[13];
    byte child_84_0h_privKey[32];
    byte child_84_0h_pubKey[33];
    byte child_84_0h_chainCode[32];
    byte child_84_0h_privPrefix[13];
    byte child_84_0h_pubPrefix[13];
    byte child_84_0h_0h_privKey[32];
    byte child_84_0h_0h_pubKey[33];
    byte child_84_0h_0h_chainCode[32];
    byte child_84_0h_0h_privPrefix[13];
    byte child_84_0h_0h_pubPrefix[13];
    byte child_84_0h_0h_0_privKey[32];
    byte child_84_0h_0h_0_pubKey[33];
    byte child_84_0h_0h_0_chainCode[32];
    byte child_84_0h_0h_0_privPrefix[13];
    byte child_84_0h_0h_0_pubPrefix[13];
    byte child_84_0h_0h_0_0_privKey[32];
    byte child_84_0h_0h_0_0_pubKey[33];
    byte child_84_0h_0h_0_0_chainCode[32];
    byte child_84_0h_0h_0_0_privPrefix[13];
    byte child_84_0h_0h_0_0_pubPrefix[13];
    
    unsigned int index_hard = 2147483648;
    
    deriveHardChildPrivKey(master_privKey, master_chainCode, index_hard+84, child_84_privKey, child_84_chainCode);
    generatePubKeyFromPrivKey(child_84_privKey, child_84_pubKey);
    serializationPrefix(const_cast<char*>("zprv"), 0x01, master_pubKey, index_hard+84, child_84_privPrefix);
    serializationPrefix(const_cast<char*>("zpub"), 0x01, master_pubKey, index_hard+84, child_84_pubPrefix);
    
    deriveHardChildPrivKey(child_84_privKey, child_84_chainCode, index_hard, child_84_0h_privKey, child_84_0h_chainCode);
    generatePubKeyFromPrivKey(child_84_0h_privKey, child_84_0h_pubKey);
    serializationPrefix(const_cast<char*>("zprv"), 0x02, child_84_pubKey, index_hard, child_84_0h_privPrefix);
    serializationPrefix(const_cast<char*>("zpub"), 0x02, child_84_pubKey, index_hard, child_84_0h_pubPrefix);
    
    deriveHardChildPrivKey(child_84_0h_privKey, child_84_0h_chainCode, index_hard, child_84_0h_0h_privKey, child_84_0h_0h_chainCode);
    generatePubKeyFromPrivKey(child_84_0h_0h_privKey, child_84_0h_0h_pubKey);
    serializationPrefix(const_cast<char*>("zprv"), 0x03, child_84_0h_pubKey, index_hard, child_84_0h_0h_privPrefix);
    serializationPrefix(const_cast<char*>("zpub"), 0x03, child_84_0h_pubKey, index_hard, child_84_0h_0h_pubPrefix);

    deriveSoftChildPrivKey(child_84_0h_0h_privKey, child_84_0h_0h_pubKey, child_84_0h_0h_chainCode, 0, child_84_0h_0h_0_privKey, child_84_0h_0h_0_chainCode);
    generatePubKeyFromPrivKey(child_84_0h_0h_0_privKey, child_84_0h_0h_0_pubKey);
    serializationPrefix(const_cast<char*>("zprv"), 0x04, child_84_0h_0h_pubKey, 0, child_84_0h_0h_0_privPrefix);
    serializationPrefix(const_cast<char*>("zpub"), 0x04, child_84_0h_0h_pubKey, 0, child_84_0h_0h_0_pubPrefix);

    deriveSoftChildPrivKey(child_84_0h_0h_0_privKey, child_84_0h_0h_0_pubKey, child_84_0h_0h_0_chainCode, 0, child_84_0h_0h_0_0_privKey, child_84_0h_0h_0_0_chainCode);
    generatePubKeyFromPrivKey(child_84_0h_0h_0_0_privKey, child_84_0h_0h_0_0_pubKey);
    serializationPrefix(const_cast<char*>("zprv"), 0x05, child_84_0h_0h_0_pubKey, 0, child_84_0h_0h_0_0_privPrefix);
    serializationPrefix(const_cast<char*>("zpub"), 0x05, child_84_0h_0h_0_pubKey, 0, child_84_0h_0h_0_0_pubPrefix);

    byte master_privKey_serialized[82];
    byte master_pubKey_serialized[82];
    std::string master_privKey_serialized_str;
    std::string master_pubKey_serialized_str;
    serializeKey(master_privPrefix, master_privKey, master_chainCode, master_privKey_serialized, master_privKey_serialized_str);
    serializeKey(master_pubPrefix, master_pubKey, master_chainCode, master_pubKey_serialized, master_pubKey_serialized_str);
    std::string master_pubKey_addressP2WPKH = getAddressP2WPKH(master_pubKey);

    byte child_84_privKey_serialized[82];
    byte child_84_pubKey_serialized[82];
    std::string child_84_privKey_serialized_str;
    std::string child_84_pubKey_serialized_str;
    serializeKey(child_84_privPrefix, child_84_privKey, child_84_chainCode, child_84_privKey_serialized, child_84_privKey_serialized_str);
    serializeKey(child_84_pubPrefix, child_84_pubKey, child_84_chainCode, child_84_pubKey_serialized, child_84_pubKey_serialized_str);
    std::string child_84_pubKey_addressP2WPKH = getAddressP2WPKH(child_84_pubKey);

    byte child_84_0h_privKey_serialized[82];
    byte child_84_0h_pubKey_serialized[82];
    std::string child_84_0h_privKey_serialized_str;
    std::string child_84_0h_pubKey_serialized_str;
    serializeKey(child_84_0h_privPrefix, child_84_0h_privKey, child_84_0h_chainCode, child_84_0h_privKey_serialized, child_84_0h_privKey_serialized_str);
    serializeKey(child_84_0h_pubPrefix, child_84_0h_pubKey, child_84_0h_chainCode, child_84_0h_pubKey_serialized, child_84_0h_pubKey_serialized_str);
    std::string child_84_0h_pubKey_addressP2WPKH = getAddressP2WPKH(child_84_0h_pubKey);

    byte child_84_0h_0h_privKey_serialized[82];
    byte child_84_0h_0h_pubKey_serialized[82];
    std::string child_84_0h_0h_privKey_serialized_str;
    std::string child_84_0h_0h_pubKey_serialized_str;
    serializeKey(child_84_0h_0h_privPrefix, child_84_0h_0h_privKey, child_84_0h_0h_chainCode, child_84_0h_0h_privKey_serialized, child_84_0h_0h_privKey_serialized_str);
    serializeKey(child_84_0h_0h_pubPrefix, child_84_0h_0h_pubKey, child_84_0h_0h_chainCode, child_84_0h_0h_pubKey_serialized, child_84_0h_0h_pubKey_serialized_str);
    std::string child_84_0h_0h_pubKey_addressP2WPKH = getAddressP2WPKH(child_84_0h_0h_pubKey);

    byte child_84_0h_0h_0_privKey_serialized[82];
    byte child_84_0h_0h_0_pubKey_serialized[82];
    std::string child_84_0h_0h_0_privKey_serialized_str;
    std::string child_84_0h_0h_0_pubKey_serialized_str;
    serializeKey(child_84_0h_0h_0_privPrefix, child_84_0h_0h_0_privKey, child_84_0h_0h_0_chainCode, child_84_0h_0h_0_privKey_serialized, child_84_0h_0h_0_privKey_serialized_str);
    serializeKey(child_84_0h_0h_0_pubPrefix, child_84_0h_0h_0_pubKey, child_84_0h_0h_0_chainCode, child_84_0h_0h_0_pubKey_serialized, child_84_0h_0h_0_pubKey_serialized_str);
    std::string child_84_0h_0h_0_pubKey_addressP2WPKH = getAddressP2WPKH(child_84_0h_0h_0_pubKey);
    
    byte child_84_0h_0h_0_0_privKey_serialized[82];
    byte child_84_0h_0h_0_0_pubKey_serialized[82];
    std::string child_84_0h_0h_0_0_privKey_serialized_str;
    std::string child_84_0h_0h_0_0_pubKey_serialized_str;
    serializeKey(child_84_0h_0h_0_0_privPrefix, child_84_0h_0h_0_0_privKey, child_84_0h_0h_0_0_chainCode, child_84_0h_0h_0_0_privKey_serialized, child_84_0h_0h_0_0_privKey_serialized_str);
    serializeKey(child_84_0h_0h_0_0_pubPrefix, child_84_0h_0h_0_0_pubKey, child_84_0h_0h_0_0_chainCode, child_84_0h_0h_0_0_pubKey_serialized, child_84_0h_0h_0_0_pubKey_serialized_str);
    std::string child_84_0h_0h_0_0_pubKey_addressP2WPKH = getAddressP2WPKH(child_84_0h_0h_0_0_pubKey);

    std::cout << "\n======= DERIVATION TREE FOR BIP 84 ========\n";
    std::cout << "master_privKey_serialized:               " << master_privKey_serialized_str << std::endl;
    std::cout << "master_pubKey_serialized:                " << master_pubKey_serialized_str << std::endl;
    std::cout << "master_pubKey_addressP2WPKH:             " << master_pubKey_addressP2WPKH << std::endl;
    std::cout << std::endl;
    std::cout << "child_84_privKey_serialized:             " << child_84_privKey_serialized_str << std::endl;
    std::cout << "child_84_pubKey_serialized:              " << child_84_pubKey_serialized_str << std::endl;
    std::cout << "child_84_pubKey_addressP2WPKH:           " << child_84_pubKey_addressP2WPKH << std::endl;
    std::cout << std::endl;
    std::cout << "child_84_0h_privKey_serialized:          " << child_84_0h_privKey_serialized_str << std::endl;
    std::cout << "child_84_0h_pubKey_serialized:           " << child_84_0h_pubKey_serialized_str << std::endl;
    std::cout << "child_84_0h_pubKey_addressP2WPKH:        " << child_84_0h_pubKey_addressP2WPKH << std::endl;
    std::cout << std::endl;
    std::cout << "child_84_0h_0h_privKey_serialized:       " << child_84_0h_0h_privKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_pubKey_serialized:        " << child_84_0h_0h_pubKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_pubKey_addressP2WPKH:     " << child_84_0h_0h_pubKey_addressP2WPKH << std::endl;
    std::cout << std::endl;
    std::cout << "child_84_0h_0h_0_privKey_serialized:     " << child_84_0h_0h_0_privKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_0_pubKey_serialized:      " << child_84_0h_0h_0_pubKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_0_pubKey_addressP2WPKH    " << child_84_0h_0h_0_pubKey_addressP2WPKH << std::endl;
    std::cout << std::endl;
    std::cout << "child_84_0h_0h_0_0_privKey_serialized:   " << child_84_0h_0h_0_0_privKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_0_0_pubKey_serialized:    " << child_84_0h_0h_0_0_pubKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_0_0_pubKey_addressP2WPKH  " << child_84_0h_0h_0_0_pubKey_addressP2WPKH << std::endl;

    return 0;
}
