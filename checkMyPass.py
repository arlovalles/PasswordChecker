import requests
import hashlib
import sys

def request_api_data(query_char):
    '''
    Query Password Hashes based on SHA1 first 5 chars
    '''
    url = 'https://api.pwnedpasswords.com/range'
    response = requests.get(f"{url}/{query_char}")
    if response.status_code != 200:
        raise RuntimeError(f"Error Retrieving: {response.status_code} - {query_char}")
    return response    

def get_password_leaks_count(hashes, hash_to_check)->int:
    '''
    Extract Count for Password hash that matches in the results
    '''
    result = 0
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for hash, count in hashes:
        if hash == hash_to_check:
            result = int(count)
            break
    return result        

def pwned_api_check(password:str='', encoding:str='utf-8'):    
    '''
    Using SHA1, request from pwnedpasswords.com number of times this 'password' has been pwned. 
    '''
    sha1_password = hashlib.sha1(password.encode(encoding)).hexdigest().upper()
    first5Chars, remainingChars = sha1_password[:5], sha1_password[5:] 
    response = request_api_data(first5Chars)    
    return get_password_leaks_count(response, remainingChars)


def main(args):
    '''
    Process an array of password arguments
    '''
    for pwd in args:
        count = pwned_api_check(password=pwd)
        if count > 0:
            print(f"{pwd} has been breached {count} times.") 
        else:
            print(f"{pwd} was not found.") 
    return

if __name__ == '__main__':
    if len(sys.argv) > 1:
        main(sys.argv[1:])
    else:
        print("Running in Demo Mode.")
        pwned_api_check(password='password1234')

    
