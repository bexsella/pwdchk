# pwdchk
Check the state of a password against the public API of the Pwned Passwords database.

Functionally of little use and really only used as a way to decrustify my knowledge of the Go standard library, and to satisfy a curiosity of how many times "timtam" appears in the data set (2493 times as it turned out, "timtams" 116 times).

Only the first five characters of the SHA1 hash of any passwords entered are sent in the GET request, as per the API, probably don't use it for real and in use passwords, or if you do be sure to clear your terminal history. Use it as an excuse to go down memory lane and try out those early, and see how many times they crop up in the data set (one of mine has cropped up 4883 times).

## Reference
https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/
https://haveibeenpwned.com/API/v2
