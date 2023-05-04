import datetime
import multiprocessing
import re
import requests
from tqdm import tqdm

def check_ip_reputation(ip_address):
    # AbuseIPDB API key
    abuse_ipdb_url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90&verbose=yes'
    abuse_ipdb_headers = {'Key': 'a7004fd4c69aa2f1cfa420a43a859ea7ab569f39e7d6db714c510521061b0fb313a07312b275bfc6',
                          'Accept': 'application/json'}
    abuse_ipdb_response = requests.get(abuse_ipdb_url, headers=abuse_ipdb_headers)

    #VirusTotal API key
    virus_total_url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    virus_total_headers = {'x-apikey': '2b9c5be62907cd383c2dfda2896f4bafde82586aa31591666c4499a043230088'}
    virus_total_response = requests.get(virus_total_url, headers=virus_total_headers)

    # Check the AbuseIPDB result
    if abuse_ipdb_response.status_code == 200:
        abuse_ipdb_data = abuse_ipdb_response.json()
        abuse_ipdb_score = abuse_ipdb_data['data']['abuseConfidenceScore']
        if abuse_ipdb_score > 50:
            abuse_ipdb_result = 'Malicious'
            abuse_ipdb_category = abuse_ipdb_data['data']['reports']
        else:
            abuse_ipdb_result = 'Not Malicious'

        abuse_ipdb_last_reported_at = abuse_ipdb_data['data']['lastReportedAt'] or 'None'

        if abuse_ipdb_last_reported_at != 'None':
            dt = datetime.datetime.fromisoformat(abuse_ipdb_last_reported_at[:-6])
            abuse_ipdb_last_reported_at = dt.strftime('%d-%m-%Y')

        abuse_ipdb_isp = abuse_ipdb_data['data']['isp'] or 'None'
        abuse_ipdb_country_name = abuse_ipdb_data['data']['countryName'] or 'None'
    else:
        abuse_ipdb_result = 'Error'
        abuse_ipdb_last_reported_at = 'N/A'
        abuse_ipdb_isp = 'N/A'
        abuse_ipdb_country_name = 'N/A'

    # Check the VirusTotal result
    if virus_total_response.status_code == 200:
        virus_total_data = virus_total_response.json()
        virus_total_malicious = virus_total_data['data']['attributes']['last_analysis_stats']['malicious']
        if virus_total_malicious > 0:
            virus_total_result = 'Malicious'
        else:
            virus_total_result = 'Not Malicious'
    else:
        virus_total_result = 'Error'

    # Return the results as a dictionary
    return {
        'IP Address': ip_address,
        'AbuseIPDB Result': abuse_ipdb_result,
        'AbuseIPDB Score': abuse_ipdb_score,
        'Last Reported At': abuse_ipdb_last_reported_at,
        'AbuseIPDB ISP': abuse_ipdb_isp,
        'Country Name': abuse_ipdb_country_name,
        'VirusTotal Result': virus_total_result,
        'VirusTotal Malicious': virus_total_malicious
    }

def validate_ip_address(ip_address):
    """
    Validates the format of an IP address
    Returns True if the format is valid, False otherwise
    """
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(pattern, ip_address))


if __name__ == '__main__':
    while True:
        # Prompt the user to enter a list of IP addresses separated by commas or new lines
        ip_list = input('Enter a list of IP addresses separated by commas or new lines: ')

        # Split the input into a list of IP addresses

        ip_addresses = [ip.strip() for ip in ip_list.replace('\n', ',').split(',')]

        while True:
            user_input = input()

            # if user pressed Enter without a value, break out of loop
            if user_input == '':
                break
            else:
                ip_addresses.append(user_input)

        # Check the reputation of each IP address using the AbuseIPDB and VirusTotal APIs
        valid_ip_addresses = []
        invalid_ip_addresses = []
        results = []
        for ip_address in ip_addresses:
            if validate_ip_address(ip_address):
                valid_ip_addresses.append(ip_address)
            else:
                invalid_ip_addresses.append(ip_address)

        # for valid_ip_add in valid_ip_addresses:
        #     result = check_ip_reputation(valid_ip_add)
        #     results.append(result)

        with tqdm(total=len(valid_ip_addresses), leave=True, unit=' items', desc='I am checking for you:') as pbar:
            # For Multiprocessing
            pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())

            # Make parallel requests to the API using the multiprocessing pool
            for result in pool.imap_unordered(check_ip_reputation, valid_ip_addresses):
                results.append(result)
                pbar.update()

        # Close the pool to prevent memory leaks
        pool.close()
        pool.join()

        # Print the results in a table format
        print(f"{'IP Address':<20}"
              f"{'AbuseIPDB Result':<20}"
              f"{'AbuseIPDB Score':<20}"
              f"{'VirusTotal Result':<20}"
              f"{'VirusTotal Malicious':<30}"
              f"{'Last Reported At':<30}"
              f"{'Country Name':<30}"
              f"{'AbuseIPDB ISP':<30}"
              )

        for result in results:
            print(f"{result['IP Address']:<20}"
                  f"{result['AbuseIPDB Result']:<20}"
                  f"{result['AbuseIPDB Score']:<20}"
                  f"{result['VirusTotal Result']:<20}"
                  f"{result['VirusTotal Malicious']:<30}"
                  f"{result['Last Reported At']:<30}"
                  f"{result['Country Name']:<30}"
                  f"{result['AbuseIPDB ISP']:<30}"
                  )


        if invalid_ip_addresses != []:
            print("\nInvalid IP addresses:")
            for ip_address in invalid_ip_addresses:
                print(ip_address)
        else:
            print("\n You can relax now CyberHero :)")



        user_input = input("\n Press 1 to continue or 0 to exit: ")
        if user_input == "0":
            break
