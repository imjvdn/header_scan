import email
import sys

def check_headers(headers):
    # Check the "From" header
    if "From" in headers:
        from_header = headers["From"]
        # Check if the "From" header contains a suspicious domain
        if "suspicious_domain.com" in from_header:
            print("Suspicious 'From' header:", from_header)
            return True
    # Check the "To" header
    if "To" in headers:
        to_header = headers["To"]
        # Check if the "To" header contains a suspicious domain
        if "suspicious_domain.com" in to_header:
            print("Suspicious 'To' header:", to_header)
            return True
    # Check the "Subject" header
    if "Subject" in headers:
        subject_header = headers["Subject"]
        # Check if the "Subject" header contains a suspicious keyword
        if "suspicious keyword" in subject_header:
            print("Suspicious 'Subject' header:", subject_header)
            return True
    return False

def main():
    # Parse the command line arguments
    if len(sys.argv) != 2:
        print("Usage: python email_checker.py <email_file>")
        sys.exit(1)
    email_file = sys.argv[1]

    # Read the email from the file
    with open(email_file, 'r') as fp:
        msg = email.message_from_file(fp)

    # Get the headers of the email
    headers = dict(msg.items())
    # Check if the headers contain any suspicious information
    if check_headers(headers):
        print("This email may be a phishing email.")
    else:
        print("This email is not a phishing email.")

if __name__ == '__main__':
    main()
