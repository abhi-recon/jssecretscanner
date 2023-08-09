import gc
import re
import sys
import requests
import threading
import time
from colorama import init, Fore, Back, Style
from tqdm import tqdm
import argparse

init(autoreset=True)  # Initialize colorama

regex_descriptions = {
    'sensitive_data' : 'sensitive data found',
    'google_api': "Google API Key",
    'google_captcha': "Google Captcha Site Key",
    'google_oauth': "Google OAuth Access Token",
    'amazon_aws_access_key_id': "Amazon AWS Access Key ID",
    'amazon_mws_auth_toke': "Amazon MWS Authentication Token",
    'amazon_aws_url': "Amazon AWS URL",
    'facebook_access_token': 'Matches a Facebook access token',
    'authorization_basic': 'Matches a Basic Authorization header',
    'authorization_bearer': 'Matches a Bearer Authorization header',
    'authorization_api': 'Matches an API key in Authorization header',
    'mailgun_api_key': 'Matches a Mailgun API key',
    'twilio_api_key': 'Matches a Twilio API key',
    'twilio_account_sid': 'Matches a Twilio Account SID',
    'twilio_app_sid': 'Matches a Twilio App SID',
    'paypal_braintree_access_token': 'Matches a PayPal Braintree Access Token with specific format.',
    'square_oauth_secret': 'Matches a Square OAuth Secret',
    'square_access_token': 'Matches a Square Access Token',
    'stripe_standard_api': 'Matches a Stripe Standard API key',
    'stripe_restricted_api': 'Matches a Stripe Restricted API key',
    'github_access_token': 'Matches a GitHub Access Token with certain format.',
    'rsa_private_key': 'Matches the beginning of an RSA Private Key.',
    'ssh_dsa_private_key': 'Matches the beginning of a DSA Private Key.',
    'ssh_dc_private_key': 'Matches the beginning of an EC Private Key.',
    'pgp_private_block': 'Matches the beginning of a PGP Private Key Block.',
    'json_web_token': 'Matches a JSON Web Token (JWT) with specific format.',
    'api_token': 'Matches an API token in the form ',
    'uuid': 'Matches a UUID',
}

embedded_regex_patterns = [
    re.compile(r'(?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api\.googlemaps|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn\.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env\.heroku_api_key|env\.sonatype_password|eureka\.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}["\']([0-9a-zA-Z\-_=]{8,64})["\']'),
    re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'),
    re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'),
    re.compile(r'6L[0-9A-Za-z\-_]{38}|^6[0-9a-zA-Z_-]{39}$'),
    re.compile(r'ya29\\.[0-9A-Za-z\\-]+'),
    re.compile(r'A[SK]IA[0-9A-Z]{16}'),
    re.compile(r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    re.compile(r's3\\.amazonaws\\.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws\\.com'),
    re.compile(r'[a-zA-Z0-9-\\._]+\\.s3\\.amazonaws\\.com'),
    re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+'),
    re.compile(r'basic [a-zA-Z0-9=:_\\+\\/-]{5,100}'),
    re.compile(r'api[key|_key|\\s+]+[a-zA-Z0-9_\\-]{5,100}'),
    re.compile(r'key-[0-9a-zA-Z]{32}'),
    re.compile(r'SK[0-9a-fA-F]{32}'),
    re.compile(r'AC[a-zA-Z0-9_\\-]{32}'),
    re.compile(r'AP[a-zA-Z0-9_\\-]{32}'),
    re.compile(r'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}'),
    re.compile(r'sq0csp-[ 0-9A-Za-z\\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\\-_]{22,43}'),
    re.compile(r'sqOatp-[0-9A-Za-z\\-_]{22}|EAAA[a-zA-Z0-9]{60}'),
    re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
    re.compile(r'rk_live_[0-9a-zA-Z]{24}'),
    re.compile(r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*'),
    re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
    re.compile(r'-----BEGIN DSA PRIVATE KEY-----'),
    re.compile(r'-----BEGIN EC PRIVATE KEY-----'),
    re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    re.compile(r'ey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$'),
    re.compile(r'"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"'),
    re.compile(r'([-]+BEGIN [^\\s]+ PRIVATE KEY[-]+[\\s]*[^-]*[-]+END [^\\s]+ PRIVATE KEY[-]+)'),
    re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
]

def extract_matched_content(regex_list, links, verbose=False):
    matched_content = {regex: {} for regex in regex_list}

    def fetch_content(link):
        try:
            response = requests.get(link)
            if response.status_code == 200:
                lines = [line.strip() for line in response.text.splitlines() if line.strip()]  # Remove empty lines
                return '\n'.join(lines)  # Reconstruct content without newlines
            else:
                if verbose:
                    print(f"{Back.RED}{Fore.WHITE}Failed to fetch content from {link}. Status code: {response.status_code}{Style.RESET_ALL}")
        except Exception as e:
            if verbose:
                print(f"{Back.RED}{Fore.WHITE}An error occurred while fetching content from {link}: {e}{Style.RESET_ALL}")
        return None

    def process_link(link):
        content = fetch_content(link)
        if content is not None:
            for regex in regex_list:
                matches = regex.findall(content)
                if matches:
                    matched_content[regex][link] = matches
                    if verbose:
                        print(f"{Fore.GREEN}Found matches in {link} for regex '{regex.pattern}'.{Style.RESET_ALL}")
                elif verbose:
                    print(f"{Fore.YELLOW}No matches found in {link} for regex '{regex.pattern}'.{Style.RESET_ALL}")
        pbar.update(1)

    output_file_path = "output.txt"  # Change this to your desired output file name
    output_file = open(output_file_path, "w")  # Open output file for writing

    with tqdm(total=len(links), desc="Progress", unit="link") as pbar:
        threads = []
        for link in links:
            thread = threading.Thread(target=process_link, args=(link,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    for regex, links_data in matched_content.items():
        output_file.write(f"\nMatches for regex '{regex.pattern}':\n")
        if links_data:
            for link, matches in links_data.items():
                output_file.write(f"\nMatches from {link}:\n")
                for match in matches:
                    output_file.write(f"{match}\n")

    output_file.close()  # Close the output file

    return matched_content


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search for sensitive data in web content from a list of links.")
    parser.add_argument("-i", "--input", required=True, help="Path to the file containing links.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode.")

    args = parser.parse_args()
    links_file_path = args.input
    verbose_mode = args.verbose

    try:
        with open(links_file_path, 'r') as links_file:
            links = [link.strip() for link in links_file.readlines()]
    except FileNotFoundError:
        print(f"{Back.RED}{Fore.WHITE}Links file not found.{Style.RESET_ALL}")
        sys.exit(1)

    # Remove leading and trailing whitespaces from each link
    links = [link.strip() for link in links]

    matched_content = extract_matched_content(embedded_regex_patterns, links, verbose=verbose_mode)

    if matched_content:
        for regex, links_data in matched_content.items():
            print(f"\n{Fore.CYAN}Matches for regex '{regex.pattern}':{Style.RESET_ALL}")
            if links_data:
                for link, matches in links_data.items():
                    print(f"\n{Fore.BLUE}Matches from {link}:{Style.RESET_ALL}")
                    for match in matches:
                        print(f"{Fore.GREEN}{match}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}No matches found for regex '{regex.pattern}'.{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}No matches found.{Style.RESET_ALL}")

    # Explicitly free up memory
    matched_content = None
    gc.collect()

