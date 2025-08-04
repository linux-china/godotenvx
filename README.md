Dotenvx Go SDK
==================

# Get Started

Installation:

```shell
$ go get github.com/linux-china/godotenvx
```

Use [dotenvx cli](https://github.com/linux-china/dotenvx-rs) to create `.env` file:

```shell
$ dotenvx init
$ dotenvx set S3_ACCESS_KEY_ID xxx
$ dotenvx set S3_SECRET_ACCESS_KEY yyyy
$ dotenvx encrypt
```

Then in your Go app you can load `.env` into environment variables:

```go
package main

import (
	"log"
	"os"

	dotenvx "github.com/linux-china/godotenvx"
)

func main() {
	err := dotenvx.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	s3AccessKeyId := os.Getenv("S3_ACCESS_KEY_ID")
	s3SecretAccessKey := os.Getenv("S3_SECRET_ACCESS_KEY")
	println(s3AccessKeyId, s3SecretAccessKey)
}
```

# References

* [GoDotEnv](https://github.com/joho/godotenv): Loads environment variables from .env files by Golang
* [Dotenvx](https://dotenvx.com/):
* [eciesgo](https://github.com/ecies/go): Elliptic Curve Integrated Encryption Scheme for secp256k1, written in Go with
  minimal dependencies