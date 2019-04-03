package CryptoLib

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/jchavannes/go-pgp/pgp"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/pbkdf2"
)

var mu sync.Mutex

// region PGP

//structure for obtaining keys
type PgpKeys struct {
	PrivateKey string
	PublicKey  string
}

const RSA_BITS int = 2048

//PGPGenerateKeyPair - generate a pair of private and public keys
func PGPGenerateKeyPair(name, comment, email, password string) (keys *PgpKeys, err error) {
	config := packet.Config{RSABits: RSA_BITS}
	entity, err := openpgp.NewEntity(name, comment, email, &config)

	if err != nil {
		return nil, err
	}

	for _, en := range entity.Identities {
		err := en.SelfSignature.SignUserId(en.UserId.Id, entity.PrimaryKey, entity.PrivateKey, nil)
		if err != nil {
			return nil, err
		}
	}

	for _, sb := range entity.Subkeys {
		sb.Sig.SignKey(entity.PrimaryKey, entity.PrivateKey, nil)
	}

	var bufPub = new(bytes.Buffer)

	pk, err := pgpEncryptPrivateKey(entity.PrivateKey, password)
	if err != nil {
		return nil, err
	}

	pgpCreatePublicKey(bufPub, entity.PrimaryKey)

	_keys := PgpKeys{pk, bufPub.String()}

	return &_keys, err
}

//PGPEncrypt - encrypt by public key
func PGPEncrypt(publicKey, message string) (msg string, err error) {
	mu.Lock()
	defer mu.Unlock()
	pubEnt, err := pgp.GetEntity([]byte(publicKey), []byte{})
	if err != nil {
		return
	}
	pubEnt.PrimaryKey.KeyId = 0
	m, err := pgp.Encrypt(pubEnt, []byte(message))

	return string(m), err
}

//PGPDecrypt - decrypt by private key
func PGPDecrypt(privateKey, message, passphrase string) (msg string, err error) {
	mu.Lock()
	defer mu.Unlock()
	b, r := pem.Decode([]byte(privateKey))
	if len(r) > 0 {
		return "", errors.New("Error Key: extra data")
	}

	dt, err := x509.DecryptPEMBlock(b, []byte(passphrase))
	if err != nil {
		return
	}

	pk, err := x509.ParsePKCS1PrivateKey(dt)
	if err != nil {
		return
	}

	tm := time.Now()
	packetPriv := packet.NewRSAPrivateKey(tm, pk)
	packetPub := packet.NewRSAPublicKey(tm, &pk.PublicKey)

	ent, err := pgpCreateEntityFromKeys(packetPub, packetPriv)
	if err != nil {
		return
	}

	m, err := pgp.Decrypt(ent, []byte(message))
	return string(m), err
}

//PGPPrivateKeyChangePassword - change password for private key
func PGPPrivateKeyChangePassword(privateKey, oldPassword, newPassword string) (pk string, err error) {
	b, r := pem.Decode([]byte(privateKey))
	if len(r) > 0 {
		return "", errors.New("Error Key: extra data")
	}

	dt, err := x509.DecryptPEMBlock(b, []byte(oldPassword))
	if err != nil {
		return
	}

	privKey, err := x509.ParsePKCS1PrivateKey(dt)
	if err != nil {
		return
	}

	pcPriv := packet.NewRSAPrivateKey(time.Now(), privKey)

	return pgpEncryptPrivateKey(pcPriv, newPassword)
}

//PGPPublicKeyFromPrivate - obtain the public key by private key
func PGPPublicKeyFromPrivate(privateKey, passphrase string) (publicKey string, err error) {
	b, r := pem.Decode([]byte(privateKey))
	if len(r) > 0 {
		return "", errors.New("Error Key: extra data")
	}

	dt, err := x509.DecryptPEMBlock(b, []byte(passphrase))
	if err != nil {
		return
	}

	pk, err := x509.ParsePKCS1PrivateKey(dt)
	if err != nil {
		return
	}

	buf := new(bytes.Buffer)
	w, err := armor.Encode(buf, openpgp.PublicKeyType, map[string]string{})
	if err != nil {
		return
	}

	pc := packet.NewRSAPublicKey(time.Now(), &pk.PublicKey)

	err = pc.Serialize(w)
	if err != nil {
		return
	}

	err = w.Close()

	return buf.String(), err
}

//pgpEncryptPrivateKey - encrypt the private key by password
func pgpEncryptPrivateKey(pk *packet.PrivateKey, passphrase string) (string, error) {
	privateKey, ok := pk.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("pk not rsa private key")
	}

	pb := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	block, err := x509.EncryptPEMBlock(rand.Reader, pb.Type, pb.Bytes, []byte(passphrase), x509.PEMCipherAES256)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(block)), nil
}

//pgpCreatePublicKey - create armored public key
func pgpCreatePublicKey(out io.Writer, pk *packet.PublicKey) (err error) {

	// region recover on crash
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("pgpCreatePublicKey() -> %v", e)
		}
	}()
	// endregion

	w, err := armor.Encode(out, openpgp.PublicKeyType, make(map[string]string))
	if err != nil {
		return
	}

	pgpKey := packet.NewRSAPublicKey(time.Now(), pk.PublicKey.(*rsa.PublicKey))
	err = pgpKey.Serialize(w)
	if err != nil {
		return
	}

	return w.Close()
}

//pgpCreateEntityFromKeys - needed to encrypting and decrypting a data
func pgpCreateEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) (*openpgp.Entity, error) {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: RSA_BITS,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}

	return &e, nil
}

// endregion PGP

// region AES

const BLOCK_SIZE = 32 // 32 bytes for AES-256 encrypting

//AESEncrypt - encrypt the message by aes-256
func AESEncrypt(password, message string) string {
	mu.Lock()
	defer mu.Unlock()
	plainText := []byte(message)
	key := deriveKey(password, nil)
	block, _ := aes.NewCipher(key)

	cipherText := make([]byte, aes.BlockSize+len(plainText))

	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return ""
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return base64.URLEncoding.EncodeToString(cipherText)
}

//AESDecrypt - decrypt the message by aes-256
func AESDecrypt(password, message string) (decodedmess string, err error) {
	mu.Lock()
	defer mu.Unlock()
	cipherText, err := base64.URLEncoding.DecodeString(message)
	if err != nil {
		return
	}

	key := deriveKey(password, nil)
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short! ")
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	decodedmess = string(cipherText)

	return
}

//AESSalt - random salt
func AESSalt(saltLength int) string {
	salt := make([]byte, saltLength)
	io.ReadFull(rand.Reader, salt)

	return hex.EncodeToString(salt)[:saltLength]
}

func deriveKey(passphrase string, salt []byte) []byte {
	// http://www.ietf.org/rfc/rfc2898.txt
	if salt == nil {
		salt = make([]byte, 8)
		// rand.Read(salt)
	}

	return pbkdf2.Key([]byte(passphrase), salt, 1000, BLOCK_SIZE, sha256.New)
}

// endregion AES

// region HASH

//HashSha256 - sha256 hash in bytes
func HashSha256(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

//HashHexSha256 - sha256 hash in hex string
func HashHexSha256(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// endregion HASH

// region Codec

//Base64Encode - base64 encoding
func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

//Base64Decode - base64 decoding
func Base64Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

//HexEncode - hex encoding
func HexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

//HexDecode - hex decoding
func HexDecode(data string) ([]byte, error) {
	return hex.DecodeString(data)
}

// endregion Codec
