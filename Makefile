REPORTER = dot

install:
	npm install

dev:
	cake dev

build:
	cake build

test:
	cake test

tdd:
	mocha -c -w -b --compilers coffee:coffee-script

gen_test_keys:
	# openssl genrsa -des3 -passout pass:nosecret -out privkey.pem 2048
	openssl genrsa -out test/rsa_key.pem 2048
	openssl rsa -in test/rsa_key.pem -pubout > test/rsa_pubkey.pem
	# Generate the RSA keys and certificate
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -sha1 -subj \
		'/C=US/ST=CA/L=San Francisco /CN=www.hashgo.com' -keyout \
		test/mytest-rsakey.pem -out test/mytest-rsacert.pem
	openssl pkcs12 -passout pass:notasecret -export -in test/mytest-rsacert.pem -inkey test/mytest-rsakey.pem -out test/test-myrsacert.pi12 -name "Testing PKCS12 Certificate"

all: install build test

.PHONY: all 
