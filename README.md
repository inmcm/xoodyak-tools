[![Go Report Card](https://goreportcard.com/badge/github.com/inmcm/xoodyak-tools)](https://goreportcard.com/report/github.com/inmcm/xoodyak-tools)

# xoodyak-tools

Collection of command-line utilities to use the Xoodyak cryptographic primitives as defined in
the [NIST LWC Competition](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf)

## Installation

If you have Go >=1.17 already installed, you can build/install the latest version of the tools with:
```sh
go install github.com/inmcm/xoodyak-tools/...@latest
```


## Hashing

The `xoodyak-hash` tool calculate the Xoodyak hash on a provided file or files.

```sh
$ xoodyak-hash test.txt test.bin
5c9a95363d79b2157cbdfff49dddaf1f20562dc64644f2d28211478537e6b29a test.txt (12 bytes)
00186bfa025d9079c988cbddebdc3a5b9a03a018df487c28f01d4ade9c8afc70 test.bin (1024 bytes)
```

Input can be delivered via STDIN pipe as well:
```sh
cat test.txt | xoodyak-hash
5c9a95363d79b2157cbdfff49dddaf1f20562dc64644f2d28211478537e6b29a (12 bytes)
```

## Authenticated Encryption

The `xoodyak-crypt` tool can encrypt/decrypt provided bytes with either user provided key and nonce or generated values. A 16-byte key and nonce are required
while additional metadata (of any length) is optional.

### Configuration File Usage

The simplest operating mode is to allow for automatic generation of the required key/nonce at encryption.
```sh
% xoodyak-crypt encrypt -C cfg test.txt 
encrypt operation successful
% ls
cfg       test.txt  test.xdyk
```
This populates the configuration file with a key/nonce pair used to encrypt the provided plaintext content. The generated ciphertext and authentication tag are written to a single file.

The encrypted output can then be decrypted using the same configuration file.
Decryption requires a populated configuration file and does not generate keys or nonces
```sh
% xoodyak-crypt decrypt -C cfg test.xdyk 
decrypt operation successful
% ls
cfg        test.plain test.txt   test.xdyk
```
The output should match the original input file in size and content
```sh
% xoodyak-hash test.txt test.plain 
d06970bd9c30ab9b1cfa58f225df7241f5c8e5330cb119393e540ffd81253779 test.txt (13 bytes) 
d06970bd9c30ab9b1cfa58f225df7241f5c8e5330cb119393e540ffd81253779 test.plain (13 bytes)
```

Optional metadata may also be included in the encryption/decryption process. The input must be a base64 encoded string. This value will be written into the configuration file along with the key and nonce. 

An optional output file path (absolute or relative) can also be specified.

```sh
% TIMESTAMP=$(date +%s | base64)
% echo $TIMESTAMP
MTY1NDQ1MjQ2NQo=
% xoodyak-crypt encrypt -C cfg -m $TIMESTAMP -o /tmp/test.encrypt test.txt
encrypt operation successful
% xoodyak-crypt decrypt -C cfg -o test.bin /tmp/test.encrypt
decrypt operation successful
```

The configuration file is a simple JSON format where each element is stored as a base64 encoded string. The configuration file can be pre-populated prior to encryption to allow for user provided parameters.
```sh
% cat cfg | jq .
{
  "key": "H7RG96Fb6IEg2KdKwa/r1w==",
  "nonce": "uC6hjaNBJcJwShJkRYEZwg==",
  "ad": "MTY1NDQ1MjQ2NQo="
}
```

### Direct Parameter Input

All three input parameter may also be provided as individual arguments. They may be provided as base64 encoded strings. This useful
when using ENV variables or when shell history is disabled (`set +o history`)
```sh
% KEY1=wOqv1deiY8MC+Ks9lRJg3A==
% NONCE1=nOfXZTAYOk0LocNcy8uLDw==
% AD1=Nhig4tzSTY5qn2RoIXDzbg==

% xoodyak-crypt encrypt -k "$KEY1" -n "$NONCE1" -m "$AD1" test.txt
encrypt operation successful
% xoodyak-crypt decrypt -k "$KEY1" -n "$NONCE1" -m "$AD1" test.xdyk
decrypt operation successful
```

Parameter may also be passed in as the contents of arbitrary files:

```sh
% printf "0123456789ABCDEF" > key1 # do not ever use this actual key
% printf "4444444444444444" > nonce1 # do not ever use this actual nonce
% date +%s > ad.date

% xoodyak-crypt encrypt -K key1 -N nonce1 -M ad.date test.txt
encrypt operation successful

% xoodyak-crypt decrypt -K key1 -N nonce1 -M ad.date test.xdyk
decrypt operation successful
```
For the key and nonce input, only the first 16 bytes of the files are read and used while the entire content of the associated metadata argument file is used.

Either of this direct approaches can be combined with the `-C` configuration file argument to allow saving the input parameters to a config file at encrypt time

```sh
% xoodyak-crypt encrypt -k "$KEY1" -n "$NONCE1" -m "$AD1" -C new_cfg test.txt
encrypt operation successful

% cat new_cfg| jq .
{
  "key": "wOqv1deiY8MC+Ks9lRJg3A==",
  "nonce": "nOfXZTAYOk0LocNcy8uLDw==",
  "ad": "Nhig4tzSTY5qn2RoIXDzbg=="
}
```

### STDIN/STDOUT Usage

To allow for composable shell scripting, reading and writing to `STDIN`/`STDOUT` is supported.
If no input file is provided, bytes are read from `STDIN` instead. The default output file name will being with `stdin` 

```sh
% cat test.txt | xoodyak-crypt encrypt -C cfg
encrypt operation successful
% cat stdin.xdyk | xoodyak-crypt decrypt -C cfg
decrypt operation successful
% ls stdin*
stdin.plain stdin.xdyk
```

Writing to `STDOUT`, instead of a file, can be enabled with the `-p` argument

```sh
% cat test.txt 
Hello Xoodoo
% cat test.txt | xoodyak-crypt encrypt -C cfg -p | xoodyak-crypt decrypt -C cfg -p > output
encrypt operation successful
decrypt operation successful
% cat output
Hello Xoodoo
```
