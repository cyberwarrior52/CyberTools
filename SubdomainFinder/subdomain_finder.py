import sublist3r
import socket

socket.setdefaulttimeout(10)

def find_subdomains(domain):
    print(f"Finding subdomains for {domain}...")
    try:
        subdomains = sublist3r.main(
            domain,
            savefile=None,
            ports=None,
            threads=40,
            silent=True,
            verbose=False,
            enable_bruteforce=False,
            engines=None
        )
        return subdomains
    except Exception as e:
        print(f"Error occurred: {e}")
        return []

def save_subdomains_to_file(subdomains, domain):
    filename = f"{domain}_subdomains.txt"
    with open(filename, "w") as file:
        for subdomain in subdomains:
            file.write(subdomain + "\n")
    print(f"Subdomains saved to {filename}")

if __name__ == "__main__":
    domain = input("Enter domain name (without http/https): ").strip()
    if domain:
        subdomains = find_subdomains(domain)
        print(f"Found {len(subdomains)} subdomains!")
        if subdomains:
            save_subdomains_to_file(subdomains, domain)
    else:
        print("No domain entered. Please provide a valid domain.")

