module github.com/cipherboy/testbed/g-k-w-pkcs11-import

go 1.23.2

replace github.com/openbao/go-kms-wrapping/wrappers/pkcs11/v2 v2.0.0-20241113125058-66e5465df15c => github.com/glatigny/openbao-go-kms-wrapping/wrappers/pkcs11/v2 v2.0.0-20241113125058-66e5465df15c

require github.com/openbao/go-kms-wrapping/wrappers/pkcs11/v2 v2.0.0-20241113125058-66e5465df15c

require (
	github.com/cenkalti/backoff/v3 v3.0.0 // indirect
	github.com/go-jose/go-jose/v3 v3.0.1 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.6 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/miekg/pkcs11 v1.1.2-0.20231115102856-9078ad6b9d4b // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/openbao/go-kms-wrapping/v2 v2.1.0 // indirect
	github.com/openbao/openbao/api/v2 v2.0.1 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	golang.org/x/crypto v0.24.0 // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/time v0.0.0-20220411224347-583f2d630306 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)
