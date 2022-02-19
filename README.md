# xoodyak-tools

Collection of command-line utilities to use the Xoodyak cryptographic primitives

## Installation

If you have Go already installed, you can build/install the latest version of the tools with:
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