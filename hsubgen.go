package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

var (
	hsublen int
)

type hsub struct {
	key     string
	subject string
}

func (h *hsub) hsubtest() bool {
	iv, err := hex.DecodeString(h.subject[:16])
	if err != nil {
		panic(err)
	}
	digest := sha256.New()
	digest.Write(iv)
	digest.Write([]byte(h.key))
	newhsub := hex.EncodeToString(append(iv, digest.Sum(nil)...))[:len(h.subject)]
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
	hsub := hex.EncodeToString(append(iv, digest.Sum(nil)...))
	for len(hsub) < hsublen {
		digest.Reset()
		digest.Write([]byte(hsub))
		hsub += hex.EncodeToString(digest.Sum(nil))
	}
	return hsub[:hsublen]
}

func main() {
	flag.IntVar(&hsublen, "l", 48, "Length of the hsub")
	flag.Parse()
	cmdargs := flag.Args()
	switch len(cmdargs) {
	case 1:
		if hsublen < 32 || hsublen > 80 {
			fmt.Println("Error: hsub must be between 32 and 80 characters")
			os.Exit(2)
		}
		h := new(hsub)
		h.key = cmdargs[0]
		fmt.Println(h.hsubgen())
	case 2:
		h := new(hsub)
		h.key = cmdargs[0]
		h.subject = cmdargs[1]
		if !h.hsubtest() {
			fmt.Println("Fail: hsub not generated with this key")
			os.Exit(1)
		}
		fmt.Println("Validated: hsub is valid for this key")
	default:
		fmt.Println("Usage: hsubgen [-l int] <key> [subject]")
		os.Exit(2)
	}
}

