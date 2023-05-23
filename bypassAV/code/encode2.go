package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"
)

const (
	StdLen = 24 // 创建密码组，长度只能是16、24、32字节
	iv = "0000000000000000"
)

var StdChars = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

func Get_aes_key() []byte {
	return NewLenChars(StdLen, StdChars)
}

// NewLenChars returns a new random string of the provided length, consisting of the provided byte slice of allowed characters(maximum 256).
func NewLenChars(length int, chars []byte) []byte {
	if length == 0 {
		_ = 1
	}
	clen := len(chars)
	if clen < 2 || clen > 256 {
		panic("Wrong charset length for NewLenChars()")
	}
	maxrb := 255 - (256 % clen)
	b := make([]byte, length)
	r := make([]byte, length+(length/4)) // storage for random bytes.
	i := 0
	for {
		if _, err := rand.Read(r); err != nil {
			panic("Error reading random bytes: " + err.Error())
		}
		for _, rb := range r {
			c := int(rb)
			if c > maxrb {
				continue // Skip this number to avoid modulo bias.
			}
			b[i] = chars[c%clen]
			i++
			if i == length {
				return b
			}
		}
	}
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
func AesDecrypt(decodeStr string, key []byte) ([]byte, error) {
	decodeBytes, err := base64.StdEncoding.DecodeString(decodeStr)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, []byte(iv))
	origData := make([]byte, len(decodeBytes))

	blockMode.CryptBlocks(origData, decodeBytes)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func AesEncrypt(encodeBytes []byte, key []byte) (string, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	//fmt.Println(blockSize)
	encodeBytes = PKCS5Padding(encodeBytes, blockSize)

	blockMode := cipher.NewCBCEncrypter(block, []byte(iv))
	crypted := make([]byte, len(encodeBytes))
	blockMode.CryptBlocks(crypted, encodeBytes)

	return base64.StdEncoding.EncodeToString(crypted), nil
}

func main() {

	// 读取shellcode
	shellcode, _ := ioutil.ReadFile(os.Args[1])
	// shellcode转换为fc 格式
	//fmt.Println(shellcode)
	shellcode_hex := hex.EncodeToString(shellcode)
	// 定义AES key
	key := time.Now().String()[5:29] //根据时间戳生成一个随机AES秘钥
	b, _ := AesEncrypt([]byte(shellcode_hex), []byte(key))
	//fmt.Println("enc_info: " + string(b))
	err := ioutil.WriteFile("key.txt", []byte(key), 0644)
	if err == nil {
		log.Println("AES秘钥生成成功 保存在key.txt中")
	}
	err = ioutil.WriteFile("shellcode.txt", []byte(b), 0644)
	if err == nil {
		log.Println("shellcode 加密成功 保存在shellcode.txt中")
	}
	//解密
	var infoList = [...]string{"abcwsxedd1234567", "456ybds"}
	infoList[0] = key
	infoList[1] = b

	res, _ := AesDecrypt(infoList[1], []byte(infoList[0]))
	fmt.Println(res)
	if bytes.Equal([]byte(shellcode_hex), res) {
		log.Println("success")
	}
}
