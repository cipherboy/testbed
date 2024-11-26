package main

import (
	"fmt"

	"github.com/openbao/go-kms-wrapping/wrappers/pkcs11/v2"
)

func main() {
	fmt.Println(pkcs11.EnvHsmWrapperLib)
	wrapper := pkcs11.NewWrapper()
	fmt.Println(wrapper)
}
