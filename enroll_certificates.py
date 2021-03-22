import argparse

from src.openbanking_tpp_proxy.proxy import Proxy

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Process parametes for certificate enrollment")

    parser.add_argument('--api_url', type=str, required=True,
                        help='API url needed for certificate integration')
    parser.add_argument('--tpp_id', type=str, required=True,
                        help="ID of the TPP certificate which can be found under 'subject=*'.")
    parser.add_argument('--tpp_name', type=str, required=True,
                        help="Name of TPP used for integration purposes.")
    parser.add_argument('--qwac_cert', type=str, required=True,
                        help="Path QWAC certificate in DER format.")
    parser.add_argument('--qwac_key', type=str, required=True,
                        help="Path QWAC key in PEM format.")
    parser.add_argument('--qseal_cert', type=str, required=True,
                        help="Path QSEAL certificate in DER format.")
    parser.add_argument('--qseal_key', type=str, required=True,
                        help="Path QSEAL key in PEM format.")
    parser.add_argument('--intermediate_cert', type=str, required=True,
                        help="Path intermediate certificate in DER format.")
    parser.add_argument('--root_cert', type=str, required=True,
                        help="Path root certificate in DER format.")

    args = parser.parse_args()

    # Enrollment process
    proxy = Proxy(args.qwac_cert, args.qwac_key, args.qseal_cert, args.qseal_key)
    enrollment_path = args.api_url + "/eidas/1.0/v1/enrollment"
    enrollment_response = proxy.enroll_certificates(enrollment_path,
                                                    args.intermediate_cert,
                                                    args.root_cert,
                                                    args.tpp_id,
                                                    args.tpp_name)
    print(enrollment_response.status_code)
    print(enrollment_response.content)

    # Perform connection checks
    response = proxy.proxy_request("GET", args.api_url + "/eidas/1.0/v1/consents/health-check")
    print(response.status_code)
    print(response.content)

    response = proxy.proxy_request("GET", args.api_url + "/eidas/1.0/v1/payments/health-check")
    print(response.status_code)
    print(response.content)
