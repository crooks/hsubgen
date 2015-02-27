package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"crypto/rand"
	"crypto/sha256"
)

const (
	hsublen int = 48  // New hsubs will be trimmed to this length
)

type hsub struct {
	key string
	subject string
}

func (h *hsub) hsubtest() bool {
	sublen := len(h.subject)
	if sublen <= 16 || sublen > 96 {
		os.Exit(2)
	}
	iv, err := hex.DecodeString(h.subject[:16])
	if err != nil {
		panic(err)
	}
	digest := sha256.New()
	digest.Write(iv)
	digest.Write([]byte(h.key))
	newhsub := hex.EncodeToString(append(iv, digest.Sum(nil)...))[:sublen]
	if newhsub == h.subject {
		return true
	}
	return false
}

func (h *hsub) hsubgen() string {
	iv := make([]byte, 8)
	_, err := rand.Read(iv)
	if err != nil {
		panic(err)
	}
	digest := sha256.New()
	digest.Write(iv)
	digest.Write([]byte(h.key))
	return hex.EncodeToString(append(iv, digest.Sum(nil)...))[:hsublen]
}

func main() {
	flag.Parse()
	cmdargs := flag.Args()
	switch len(cmdargs) {
	case 1:
		h := new(hsub)
		h.key = cmdargs[0]
		fmt.Println(h.hsubgen())
	case 2:
		h := new(hsub)
		h.key = cmdargs[0]
		h.subject = cmdargs[1]
		if ! h.hsubtest() {
			os.Exit(1)
		}
	default:
		fmt.Println("Usage: hsubtest <key> [subject]")
		os.Exit(2)
	}
}
