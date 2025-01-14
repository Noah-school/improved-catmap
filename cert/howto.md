Generating ssl cert


Generate a Private Key:
```
openssl genpkey -algorithm RSA -out private.key
```

Generate a Certificate Signing Request (CSR):
```
openssl req -new -key private.key -out certificate.csr
```

Generate a Self-Signed Certificate:
```
openssl req -x509 -key private.key -in certificate.csr -out certificate.crt -days 365
```