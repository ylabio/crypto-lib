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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jchavannes/go-pgp/pgp"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// region PGP

type PgpKeys struct {
	PrivateKey string
	PublicKey  string
}

//PGPEncryptPrivateKey шифрование и формирование человекочитаемого формата для закрытого ключа
func PGPEncryptPrivateKey(pk *packet.PrivateKey, passphrase string) (string, error) {
	//.MarshalPKCS1PrivateKey(pk)
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

//pgpCreatePublicKey формирование человекочитаемого формата для открытого ключа
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

//pgpCreateEntityFromKeys генерация ключевой пары для кодирования/декодирования данных
func pgpCreateEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) (*openpgp.Entity, error) {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: 4096,
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

//PGPPublicKeyFromPrivate получение открытого ключа по закрытому
func PGPPublicKeyFromPrivate(privateKey, passphrase string) (publicKey string, err error) {
	b, r := pem.Decode([]byte(privateKey))
	if len(r) == 0 {
		return "", errors.New("Error Key ")
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

//PGPPrivateKeyChangePassword смена пароля для приватного ключа
func PGPPrivateKeyChangePassword(privateKey, oldPassword, newPassword string) (pk string, err error) {
	b, r := pem.Decode([]byte(privateKey))
	if len(r) == 0 {
		return "", errors.New("Error Key ")
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

	return PGPEncryptPrivateKey(pcPriv, newPassword)
}

//PGPDecrypt дешифровака с помощью закрытого ключа
func PGPDecrypt(privateKey, message, passphrase string) (msg string, err error) {
	b, r := pem.Decode([]byte(privateKey))
	if len(r) == 0 {
		return msg, errors.New("Error Key ")
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

//PGPEncrypt шифрование с помощью открытого ключа
func PGPEncrypt(publicKey, message string) (msg string, err error) {
	pubEnt, err := pgp.GetEntity([]byte(publicKey), []byte{})
	if err != nil {
		return
	}

	m, err := pgp.Encrypt(pubEnt, []byte(message))

	return string(m), err
}

//PGPGenerateKeysPair генерация ключей
func PGPGenerateKeysPair(name, comment, email, password string) (keys *PgpKeys, err error) {
	entity, err := openpgp.NewEntity(name, comment, email, nil)

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

	//var bufPriv = new(bytes.Buffer)
	var bufPub = new(bytes.Buffer)

	bufPriv, err := PGPEncryptPrivateKey(entity.PrivateKey, password)
	if err != nil {
		return nil, err
	}

	pgpCreatePublicKey(bufPub, entity.PrimaryKey)

	_keys := PgpKeys{bufPriv, bufPub.String()}

	return &_keys, err
}

// endregion

// region AES

//AESEncrypt шифрование AES
func AESEncrypt(password, message string) string {
	plainText := []byte(message)
	block, _ := aes.NewCipher([]byte(password))

	cipherText := make([]byte, aes.BlockSize+len(plainText))

	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return ""
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	return base64.URLEncoding.EncodeToString(cipherText)
}

//AESDecrypt дешифровка сообщения AES
func AESDecrypt(password, message string) (decodedmess string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(message)
	if err != nil {
		return
	}

	block, err := aes.NewCipher([]byte(password))
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
	return "", nil
}

//AESSalt соль, для ванны))) ой для пароля.
func AESSalt(saltLength uint) string {
	salt := make([]byte, saltLength)
	io.ReadFull(rand.Reader, salt)
	return hex.EncodeToString(salt)[:saltLength]
}

// endregion AES

// region HASH

//HashSha256
func HashSha256(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

//HexSHA256
func HashHexSha256(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// endregion HASH

// region Codec

//Base64Encode кодируем base64
func Base64Encode(data []byte) string {
	buf := new(bytes.Buffer)
	enc := base64.NewEncoder(base64.StdEncoding, buf)
	enc.Write(data)
	enc.Close()
	return buf.String()
}

//Base64Decode декодируем base64
func Base64Decode(data string) ([]byte, error) {
	buf := new(bytes.Buffer)
	dec := base64.NewDecoder(base64.StdEncoding, buf)
	_, err := dec.Read([]byte(data))
	return buf.Bytes(), err
}

//Utf8Encode аналогично нижнему
func Utf8Encode(data []byte) []byte {
	return nil
}

//Utf8Decode тут вообще не понятно что делать надо, и не расписано.
func Utf8Decode(data []byte) []byte {
	return nil
}

//HexEncode кодируем hex.
func HexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

//HexDecode тут все просто, декодируем hex
func HexDecode(data string) ([]byte, error) {
	return hex.DecodeString(data)
}

//JsonEncode кодирование какой-то хрений в json. Надеюсь не прилетит какой-нибудь бинарный файл.
// хотя скорее всего на этом методе либо либа падать будет, либо будем получать лапшу непонятную.
func JsonEncode(data interface{}) (string, error) {
	d, err := json.Marshal(data)
	return string(d), err
}

//JsonDecode декодиирование json в неизвестную структуру, возможно из-за этого метода
// работать ничего не будет, потому-что как мапить подобное к Java - я не представляю, некий объект в памяти
// к веткам которого обратиться даже нельзя, потому-что о них ничего не известно
func JsonDecode(data []byte) (interface{}, error) {
	dt := make(map[string]interface{})
	err := json.Unmarshal(data, dt)
	return dt, err
}

// endregion Codec
