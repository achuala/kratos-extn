package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func hmacSHA256(data string, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func generateSHA256(input string) []byte {
	h := sha256.New()
	h.Write([]byte(input))
	return h.Sum(nil)
}

func hexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

func getSignatureKey(accessSecretKey, timeStamp, apiName, apiVersion string) []byte {
	TERMINATOR := "TERMINATOR"

	kSecret := []byte(accessSecretKey)
	kDate := hmacSHA256(timeStamp, kSecret)
	kVersion := hmacSHA256(apiVersion, kDate)
	kApi := hmacSHA256(apiName, kVersion)
	return hmacSHA256(TERMINATOR, kApi)
}

func computeSignature(accessSecretKey, payload string, headers map[string]string) string {
	ALGORITHM_KEY := "HMAC-SHA256"

	timestamp := headers["timestamp"]
	apiName := headers["api-name"]
	apiVersion := headers["api-version"]
	signingKey := getSignatureKey(accessSecretKey, timestamp, apiName, apiVersion)
	payloadHash := generateSHA256(payload)
	channel := headers["channel"]
	userId := headers["user-id"]

	request := channel + userId + hexEncode(payloadHash)
	stringToSign := ALGORITHM_KEY + timestamp + hexEncode(generateSHA256(request))
	return hexEncode(hmacSHA256(stringToSign, signingKey))
}
