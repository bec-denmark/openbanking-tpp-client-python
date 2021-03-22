from openbanking_tpp_proxy.proxy import Proxy

if __name__ == "__main__":
    #put api url here
    api_url = ""
    #put tpp id from cert file here
    tpp_id = ""
    proxy = Proxy("qwac_cert.cer", "qwac_key.key", "qseal_cert.cer", "qseal_key.key")
    enrollment_response = proxy.enroll_certificates(api_url + "/eidas/1.0/v1/enrollment", "intermediate.cer", "root.cer", tpp_id, "Awsome tpp")
    print(enrollment_response.status_code)
    print(enrollment_response.content)
    response = proxy.proxy_request("GET", api_url + "/eidas/1.0/v1/consents/health-check")
    print(response.status_code)
    print(response.content)
    response = proxy.proxy_request("GET", api_url + "/eidas/1.0/v1/payments/health-check")
    print(response.status_code)
    print(response.content)
