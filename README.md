# ahefutil
Implementation of the "Algebra Homomorphic Encryption Scheme Based on Fermat's Little Theorem" (AHEF)

## TODOS
* Umbrella CLI
* Support Radix-64 encoding (currently only HEX)
** Make choice of encoding an OPTION
* Replace json with json-ld (eat your own dogfood)
* Fix precision issues

## Usage

Generate two large random primes as private keys (keep them secret):
```{r, engine='bash', count_lines}
./genpkey -o private_keys.json -k 1024
```

Extract public key from private keys:
```{r, engine='bash', count_lines}
extract -p private_keys.json -o public_key.json
```

Use private keys to encrypt some values A=2.5 and B=1.3:
```{r, engine='bash', count_lines}
encrypt -o A.enc -p private_keys.json -v 2.5
encrypt -o B.enc -p private_keys.json -v 1.3
```

Use the public key to sum up the encrypted values:
```{r, engine='bash', count_lines}
addenc -a A.enc -b B.enc -p public_key.json -o C.enc
```

Use the private keys to decrypt the computation result:
```{r, engine='bash', count_lines}
decrypt -p private_keys.json -c C.enc
```

## Dependencies:

brew install libgcrypt
brew tap nlohmann/json
brew install nlohmann_json