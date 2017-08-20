# Digital Signature

This message singing implementation uses RSA signature algorithm for signing `x-www-form-urlencoded` data to generate a digital signature. The data is canonicalised and signed by the sender and the receiver verifies it.


## Generate a 2048-bit RSA private key ##

`$ openssl genrsa -out private_key.pem 2048`

Convert private Key to PKCS#8 format (so Java can read it)

`$ openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt`

Output public key portion in DER format (so Java can read it)

`$ openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der`

<img src="https://bitbucket.org/repo/7XoEpd/images/3887575059-DSC_1304.JPG" alt="Message Signing|Verification" align="left" width="400"/>
