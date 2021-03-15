from openbanking_tpp_proxy.proxy import Proxy

if __name__ == "__main__":
    #put api url here
    apiUrl = ""
    proxy = Proxy("qwac_cert.cer", "qwac_key.key", "qseal_cert.cer", "qseal_key.key")
    enrolmentResponse = proxy.enroll_certificates(apiUrl+"/eidas/1.0/v1/enrollment", "intermediate.cer", "root.cer", "DK-DFSA-5303", "Awsome tpp")
    print(enrolmentResponse.status_code)
    print(enrolmentResponse.content)
    response = proxy.proxy_request("GET", apiUrl+"/eidas/1.0/v1/consents/health-check")
    print(response.status_code)
    print(response.content)
    response = proxy.proxy_request("GET", apiUrl+"/eidas/1.0/v1/payments/health-check")
    print(response.status_code)
    print(response.content)
