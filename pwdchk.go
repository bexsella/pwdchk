// pwdchk written by Saxon Bell
// A simple utility to test passwords against the HIBP Pwned Passwords database.
// This file is public domain.
package main

import (
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// pwned passwords api URL
const ppUrl = "https://api.pwnedpasswords.com/range/"

// Make request to Pwned Passwords using the ranges API, return slice of
// strings for each returend entry.
func MakeRequest(sha1Prefix string) []string {
	requestUrl := fmt.Sprintf("%s%s", ppUrl, sha1Prefix)

	resp, err := http.Get(requestUrl)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	if resp.StatusCode == 200 {
		bytes, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			fmt.Println(err.Error())
			return nil
		}

		// get body as slice of strings.
		strBody := string(bytes)
		results := strings.Split(strBody, "\n")

		return results
	} else if resp.StatusCode == 429 {
		fmt.Fprintf(os.Stderr, "Too many requests, try again retry after %s seconds.\n", resp.Header.Get("Retry-After"))
	} else {
		fmt.Fprintf(os.Stderr, "Error %d, encountered.\n", resp.StatusCode)
	}

	return nil
}

// Check the last 35 characters of the password hash against the list of
// strings.
func CheckPassword(suffix string, list []string) (found bool, occurances int) {
	for _, pwdCheck := range list {
		if strings.Contains(pwdCheck, suffix) {
			// each returned string is 35 characters + colon.
			fmt.Sscanf(pwdCheck[36:], "%d", &occurances)
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
				fmt.Printf("The tested password has been previously compromised %d time(s)\n", occurances)
			} else {
				fmt.Println("Password not found in HIBP database.")
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "Must provide password (plain text or SHA1)\n")
	}
}
