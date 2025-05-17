package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/oasisprotocol/deoxysii"
)

const (
	KeySize   = 32
	NonceSize = 15
)

// Example static shared key (use secure random in production!)
var sharedKey = [KeySize]byte{1: 1}

type EncryptedRequest struct {
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
}

type CBORPayload struct {
	Message   string `cbor:"message"`
	Timestamp int64  `cbor:"timestamp"`
	Sender    string `cbor:"sender"`
}

func handleExchange(w http.ResponseWriter, r *http.Request) {
	// === Parse encrypted JSON ===
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Read error", http.StatusBadRequest)
		return
	}
	var req EncryptedRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "JSON error", http.StatusBadRequest)
		return
	}

	// === Decode base64 nonce & ciphertext ===
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil || len(nonce) != NonceSize {
		http.Error(w, "Invalid nonce", http.StatusBadRequest)
		return
	}
	ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, "Invalid ciphertext", http.StatusBadRequest)
		return
	}

	// === Initialize AEAD cipher with shared key ===
	aead, err := deoxysii.New(sharedKey[:])
	if err != nil {
		http.Error(w, "AEAD init failed", http.StatusInternalServerError)
		return
	}

	var nonceArr [NonceSize]byte
	copy(nonceArr[:], nonce)

	// === Decrypt ciphertext ===
	plaintext, err := aead.Open(nil, nonceArr[:], ciphertext, nil)
	if err != nil {
		http.Error(w, "Decryption failed", http.StatusUnauthorized)
		return
	}

	// === Decode CBOR payload ===
	var data CBORPayload
	if err := cbor.Unmarshal(plaintext, &data); err != nil {
		http.Error(w, "CBOR decode failed", http.StatusBadRequest)
		return
	}

	fmt.Println("📩 Received CBOR Payload:", data)

	// === Prepare CBOR response ===
	response := CBORPayload{
		Message:   "Hello from Go Server!",
		Timestamp: time.Now().Unix(),
		Sender:    "server-go",
	}
	encodedResp, err := cbor.Marshal(response)
	if err != nil {
		http.Error(w, "CBOR marshal error", http.StatusInternalServerError)
		return
	}

	// === Encrypt response ===
	respNonce := [NonceSize]byte{}
	copy(respNonce[:], []byte("uniqueNonceValue")) // Must be unique per message in real apps

	cipherResp := aead.Seal(nil, respNonce[:], encodedResp, nil)

	// === Return encrypted response JSON with base64 ===
	responseJSON := EncryptedRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(cipherResp),
		Nonce:      base64.StdEncoding.EncodeToString(respNonce[:]),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responseJSON)
}

func main() {
	http.HandleFunc("/exchange", handleExchange)
	fmt.Println("🚀 Listening on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}
