import csv
from feature_extraction.feature_extractor import extract_url_features

def extract_features_from_urls(phishing_file, safe_file, output_file):
    print("Generating phishing_dataset.csv...")

    with open(output_file, 'w', newline='', encoding='utf-8') as out_csv:
        writer = csv.writer(out_csv)

        header = [
            'url',
            'url_having_ip', 'url_length', 'url_short', 'having_at_symbol',
            'doubleSlash', 'prefix_suffix', 'sub_domain', 'SSLfinal_State',
            'domain_registration', 'favicon', 'port', 'https_token',
            'request_url', 'url_of_anchor', 'Links_in_tags', 'sfh',
            'email_submit', 'abnormal_url', 'redirect', 'on_mouseover',
            'rightClick', 'popup', 'iframe', 'age_of_domain', 'check_dns',
            'web_traffic', 'page_rank', 'google_index', 'links_pointing',
            'statistical', 'Result'
        ]
        writer.writerow(header)

        def process_file(filename, label):
            with open(filename, 'r', encoding='utf-8') as file:
                for line in file:
                    url = line.strip()
                    if not url:
                        continue
                    features = extract_url_features(url)
                    writer.writerow([url] + features + [label])

        process_file('github_phishing.txt', 1)
        process_file('safe_links.txt', -1)

    print("✅ Done! Dataset saved as phishing_dataset.csv")

if __name__ == '__main__':
    extract_features_from_urls('github_phishing.txt', 'safe_links.txt', 'phishing_dataset.csv')
