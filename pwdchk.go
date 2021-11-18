// pwdchk written by Saxon Bell
// A simple utility to test passwords against the HIBP Pwned Passwords database.
// This file is public domain.
package main

import (
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

// pwned passwords api URL
const ppUrl = "https://api.pwnedpasswords.com/range/"

func MakeRequest(sha1Suffix string) []string {
	return nil
}

func CheckPassword(suffix string, list []string) (found bool, occurances int) {
	for _, pwdCheck := range list {
		if strings.Contains(suffix, pwdCheck) {
			// each returned string is
			fmt.Sscanf(pwdCheck[:16], "%d", &occurances)
			return true, occurances
		}
	}

	return false, 0
}

func main() {
	var (
		isSHA1 bool
		pwdStr string
	)

	flag.BoolVar(&isSHA1, "s", false, "Input string is already a SHA1 hash.")
	flag.StringVar(&pwdStr, "p", "", "Password string (can be SHA1)")
	flag.Parse()

	if len(pwdStr) > 0 {
		if !isSHA1 {
			bytes := sha1.Sum([]byte(pwdStr))
			pwdStr = hex.EncodeToString(bytes[:])
		}

		pwdStr = strings.ToUpper(pwdStr)

		// Send first 5 characters to api
		results := MakeRequest(pwdStr[:5])

		if results != nil {
			found, occurances := CheckPassword(pwdStr[5:], results)

			if found {
				fmt.Printf("The tested password has been previously compromised %d time(s), and should be considered weak.\n", occurances)
			} else {
				fmt.Println("Password OK.")
			}
		} else {
			fmt.Fprintf(os.Stderr, "Request to PP API failed.")
		}

	} else {
		fmt.Fprintf(os.Stderr, "Must provide password (plain text or SHA1)")
	}
}
