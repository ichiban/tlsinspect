# tlsinspect

`tlsinspect` is a command line tool to inspect TLS connection details such as cipher suite or verified chains.

## Installation

```console
$ go get -u github.com/ichiban/tlsinspect
```

## Usage

To inspect TLS connection details, run it with as many URLs as you want. `tlsinspect` makes a GET request for each of them and prints the details of TLS connection. 

```console
$ tlsinspect https://example.com
{"https://example.com":{"Status":"200 OK","ContentLength":1256,"TLS":{"Version":"TLS 1.3","CipherSuite":"TLS_AES_256_GCM_SHA384","ServerName":"example.com","PeerCertificates":[{"SignatureAlgorithm":"SHA256-RSA","PublicKeyAlgorithm":"RSA","Version":3,"SerialNumber":"20925132584583406404415624503433883337","Issuer":{"Country":["US"],"Organization":["DigiCert Inc"],"CommonName":"DigiCert TLS RSA SHA256 2020 CA1"},"Subject":{"Country":["US"],"Organization":["Internet Corporation for Assigned Names and Numbers"],"Locality":["Los Angeles"],"Province":["California"],"CommonName":"www.example.org"}},{"SignatureAlgorithm":"SHA256-RSA","PublicKeyAlgorithm":"RSA","Version":3,"SerialNumber":"13567650854749339296468135199911180260","Issuer":{"Country":["US"],"Organization":["DigiCert Inc"],"OrganizationalUnit":["www.digicert.com"],"CommonName":"DigiCert Global Root CA"},"Subject":{"Country":["US"],"Organization":["DigiCert Inc"],"CommonName":"DigiCert TLS RSA SHA256 2020 CA1"}},{"SignatureAlgorithm":"SHA1-RSA","PublicKeyAlgorithm":"RSA","Version":3,"SerialNumber":"10944719598952040374951832963794454346","Issuer":{"Country":["US"],"Organization":["DigiCert Inc"],"OrganizationalUnit":["www.digicert.com"],"CommonName":"DigiCert Global Root CA"},"Subject":{"Country":["US"],"Organization":["DigiCert Inc"],"OrganizationalUnit":["www.digicert.com"],"CommonName":"DigiCert Global Root CA"}}],"VerifiedChains":[[{"SignatureAlgorithm":"SHA256-RSA","PublicKeyAlgorithm":"RSA","Version":3,"SerialNumber":"20925132584583406404415624503433883337","Issuer":{"Country":["US"],"Organization":["DigiCert Inc"],"CommonName":"DigiCert TLS RSA SHA256 2020 CA1"},"Subject":{"Country":["US"],"Organization":["Internet Corporation for Assigned Names and Numbers"],"Locality":["Los Angeles"],"Province":["California"],"CommonName":"www.example.org"}},{"SignatureAlgorithm":"SHA256-RSA","PublicKeyAlgorithm":"RSA","Version":3,"SerialNumber":"13567650854749339296468135199911180260","Issuer":{"Country":["US"],"Organization":["DigiCert Inc"],"OrganizationalUnit":["www.digicert.com"],"CommonName":"DigiCert Global Root CA"},"Subject":{"Country":["US"],"Organization":["DigiCert Inc"],"CommonName":"DigiCert TLS RSA SHA256 2020 CA1"}},{"SignatureAlgorithm":"SHA1-RSA","PublicKeyAlgorithm":"RSA","Version":3,"SerialNumber":"10944719598952040374951832963794454346","Issuer":{"Country":["US"],"Organization":["DigiCert Inc"],"OrganizationalUnit":["www.digicert.com"],"CommonName":"DigiCert Global Root CA"},"Subject":{"Country":["US"],"Organization":["DigiCert Inc"],"OrganizationalUnit":["www.digicert.com"],"CommonName":"DigiCert Global Root CA"}}]]}}}
```

<details>
<summary>To pretty print, use `jq` along with it.</summary>

```console
$ tlsinspect https://example.com | jq .
{
  "https://example.com": {
    "Status": "200 OK",
    "ContentLength": 1256,
    "TLS": {
      "Version": "TLS 1.3",
      "CipherSuite": "TLS_AES_256_GCM_SHA384",
      "ServerName": "example.com",
      "PeerCertificates": [
        {
          "SignatureAlgorithm": "SHA256-RSA",
          "PublicKeyAlgorithm": "RSA",
          "Version": 3,
          "SerialNumber": "20925132584583406404415624503433883337",
          "Issuer": {
            "Country": [
              "US"
            ],
            "Organization": [
              "DigiCert Inc"
            ],
            "CommonName": "DigiCert TLS RSA SHA256 2020 CA1"
          },
          "Subject": {
            "Country": [
              "US"
            ],
            "Organization": [
              "Internet Corporation for Assigned Names and Numbers"
            ],
            "Locality": [
              "Los Angeles"
            ],
            "Province": [
              "California"
            ],
            "CommonName": "www.example.org"
          }
        },
        {
          "SignatureAlgorithm": "SHA256-RSA",
          "PublicKeyAlgorithm": "RSA",
          "Version": 3,
          "SerialNumber": "13567650854749339296468135199911180260",
          "Issuer": {
            "Country": [
              "US"
            ],
            "Organization": [
              "DigiCert Inc"
            ],
            "OrganizationalUnit": [
              "www.digicert.com"
            ],
            "CommonName": "DigiCert Global Root CA"
          },
          "Subject": {
            "Country": [
              "US"
            ],
            "Organization": [
              "DigiCert Inc"
            ],
            "CommonName": "DigiCert TLS RSA SHA256 2020 CA1"
          }
        },
        {
          "SignatureAlgorithm": "SHA1-RSA",
          "PublicKeyAlgorithm": "RSA",
          "Version": 3,
          "SerialNumber": "10944719598952040374951832963794454346",
          "Issuer": {
            "Country": [
              "US"
            ],
            "Organization": [
              "DigiCert Inc"
            ],
            "OrganizationalUnit": [
              "www.digicert.com"
            ],
            "CommonName": "DigiCert Global Root CA"
          },
          "Subject": {
            "Country": [
              "US"
            ],
            "Organization": [
              "DigiCert Inc"
            ],
            "OrganizationalUnit": [
              "www.digicert.com"
            ],
            "CommonName": "DigiCert Global Root CA"
          }
        }
      ],
      "VerifiedChains": [
        [
          {
            "SignatureAlgorithm": "SHA256-RSA",
            "PublicKeyAlgorithm": "RSA",
            "Version": 3,
            "SerialNumber": "20925132584583406404415624503433883337",
            "Issuer": {
              "Country": [
                "US"
              ],
              "Organization": [
                "DigiCert Inc"
              ],
              "CommonName": "DigiCert TLS RSA SHA256 2020 CA1"
            },
            "Subject": {
              "Country": [
                "US"
              ],
              "Organization": [
                "Internet Corporation for Assigned Names and Numbers"
              ],
              "Locality": [
                "Los Angeles"
              ],
              "Province": [
                "California"
              ],
              "CommonName": "www.example.org"
            }
          },
          {
            "SignatureAlgorithm": "SHA256-RSA",
            "PublicKeyAlgorithm": "RSA",
            "Version": 3,
            "SerialNumber": "13567650854749339296468135199911180260",
            "Issuer": {
              "Country": [
                "US"
              ],
              "Organization": [
                "DigiCert Inc"
              ],
              "OrganizationalUnit": [
                "www.digicert.com"
              ],
              "CommonName": "DigiCert Global Root CA"
            },
            "Subject": {
              "Country": [
                "US"
              ],
              "Organization": [
                "DigiCert Inc"
              ],
              "CommonName": "DigiCert TLS RSA SHA256 2020 CA1"
            }
          },
          {
            "SignatureAlgorithm": "SHA1-RSA",
            "PublicKeyAlgorithm": "RSA",
            "Version": 3,
            "SerialNumber": "10944719598952040374951832963794454346",
            "Issuer": {
              "Country": [
                "US"
              ],
              "Organization": [
                "DigiCert Inc"
              ],
              "OrganizationalUnit": [
                "www.digicert.com"
              ],
              "CommonName": "DigiCert Global Root CA"
            },
            "Subject": {
              "Country": [
                "US"
              ],
              "Organization": [
                "DigiCert Inc"
              ],
              "OrganizationalUnit": [
                "www.digicert.com"
              ],
              "CommonName": "DigiCert Global Root CA"
            }
          }
        ]
      ]
    }
  }
}
```

</details>

### options

```console
$ tlsinspect -h
Usage of tlsinspect:
  -k, --insecure            ignore TLS verification error
  -x, --proxy URL           proxy
  -t, --timeout duration    timeout (default 5s)
  -A, --user-agent string   user agent
pflag: help requested
```

## License

Distributed under the MIT license. See ``LICENSE`` for more information.

## Contributing

1. Fork it (<https://github.com/ichiban/tlsinspect/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request
