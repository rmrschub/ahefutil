# ahefutil
Implementation of the "Algebra Homomorphic Encryption Scheme Based on Fermat's Little Theorem" (AHEF)

## TODOS
* Umbrella CLI
* Support Radix-64 encoding (currently only HEX)
** Make choice of encoding an OPTION
* Replace json with json-ld (eat your own dogfood)
* Fix precision issues

## Usage

Generate two (*very*) large random primes as private keys (keep them secret):
```{r, engine='bash', count_lines}
./genpkey -o private_keys.json -k 1024
```

Extract public key from private keys:
```{r, engine='bash', count_lines}
./extract -p private_keys.json -o public_key.json
```

Use private keys to encrypt some values A=2.5 and B=1.3:
```{r, engine='bash', count_lines}
./encrypt -p private_keys.json -o A.enc -v 2.5
./encrypt -p private_keys.json -o B.enc -v 1.3
```

Use the public key to add two encrypted numbers together:
```{r, engine='bash', count_lines}
./addenc -p public_key.json -a A.enc -b B.enc -o C.enc
```

Use the public key to subtract an encrypted number from another encrypted number:
```{r, engine='bash', count_lines}
./subenc -p public_key.json -a A.enc -b B.enc -o D.enc
```

Use the public key to multiply two encrypted numbers:
```{r, engine='bash', count_lines}
./mulenc -p public_key.json -a A.enc -b B.enc -o E.enc
```

Use the private keys to decrypt the computation results:
```{r, engine='bash', count_lines}
./decrypt -p private_keys.json -c C.enc
./decrypt -p private_keys.json -c D.enc
./decrypt -p private_keys.json -c E.enc
```


## Dependencies:

brew install libgcrypt
brew tap nlohmann/json
brew install nlohmann_json