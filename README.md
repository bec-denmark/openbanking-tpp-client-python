# Third Party Provider (TPP) client library Python version

## PSD2 - background and context information

With **[PSD2](https://en.wikipedia.org/wiki/Payment_Services_Directive#Revised_Directive_on_Payment_Services_(PSD2))** the European Union has published a [new directive on payment services in the
internal market](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32015L2366). Member States were required to adopt this directive into their national law by the
13th of January 2018. **PSD2** contains regulations of new services to be operated by so
called **Third Party Payment Service Providers (TPP)** on behalf of a Payment Service User (PSU).
The ideal behind this is enbling the consumers (PSUs) to access their accounts in the manner they prefer
not being tied to one bank's interface.

In order to be able to operate the new services for the PSUs a **TPP** needs to access the PSU's accounts,
which is usually managed by another PSP called the Account Servicing Payment Service Provider (ASPSP).

## TPP - transport layer requirements

The communication between the TPP and the ASPSP is always secured by using a TLSconnection
using TLS version 1.2 or higher. This TLS-connection is set up by the TPP. It is not necessary
to set up a new TLS-connection for each transaction, however the ASPSP might terminate an existing
TLS-connection if required by its security setting.

The TLS-connection has to be established always including client (i.e. TPP) authentication.
For this authentication the TPP has to use a qualified certificate for website authentication.
This qualified certificate has to be issued by a qualified trust service provider according
to the [eIDAS regulation](https://en.wikipedia.org/wiki/EIDAS) (eIDAS). The content of the certificate has to be compliant with the
requirements of (EBA-RTS). The certificate of the TPP has to indicate all roles
the TPP is authorised to use.

## TPP client library

## Installation

To install dependencies use `setup.py` script.

```bash
python setup.py install
```

### Purpose

This utility library helps TPP developers to properly configure and establish a secure connection.
It also addresses all HTTP headers- and message signing- related requirements.

### Basics

First, create Proxy class and provide Website Authentication Certificate and Key (wac) and signing (seal)
client certificate and key file paths. Tke certificates and keys should be in RSA format (*.cer, *.key).
For seal key the library supports password encryption however passwords are not supported for wac key.

```python
from openbanking_tpp_proxy.proxy import Proxy
proxy = Proxy("qwac_cert.cer", "qwac_key.key", "qseal_cert.cer", "qseal_key.key")
```

Next, use python class to handle communication

```python
response = proxy.proxy_request("GET", "https://some.gateway.url/eidas/1.0/v1/consents/health-check")
```

The proxy client uses Python Requests HTTP Library where returned response is a part of.
The Proxy class also supports the tpp certificate enrollment process provided in constructor.
The sample call looks as follows:

```python
enrollment_response = proxy.enroll_certificates("https://some.gateway.url/eidas/1.0/v1/enrollment", "intermediate.cer", "root.cer", "TPP_ID" , "Commertial name")
```

The sample usage can be found here: [app.py](src/app.py)

### CLI usage

CLI script provides usefull utility to perform TPP Certificate upload.
To use it properly.
#### Usage

To enroll the certificates from the shell use cli script below. Please change parameters to real ones.

**Example**

```bash
python enroll_certificates.py \
  --api_url http://example.com
  --tpp_id "NO-12345-ABC" \
  --tpp_name "Awesome TPP" \
  --qwac_cert "qwac_cert.cer" \
  --qwac_key "qwac_key.key" \
  --qseal_cert "qseal_cert.cer" \
  --qseal_key "qseal_key.key" \
  --intermediate_cert "intermediate.cer" \
  --root_cert "root.cer"
```

#### Help

To display help and information about arguments.

```bash
python enroll_certificates.py -h
```
