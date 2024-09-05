import requests
import hashlib
import sys

def request_api_data(query_char):
    '''
    Query Password Hashes based on SHA1
    '''
    url = 'https://api.pwnedpasswords.com/range'
    response = requests.get(f"{url}/{query_char}")
    if response.status_code != 200:
        raise RuntimeError(f"Error Retrieving: {response.status_code} - {query_char}")
    #print(response)
    #print(response.content)
    return response    

def get_password_leaks_count(hashes, hash_to_check):
    result = 0
    for hash in hashes:
        dta = hash.split(':')
        if dta[0] == hash_to_check:
            #print(dta)
            result = dta[1]
    return result        

def pwned_api_check(password:str='', encoding:str='utf-8'):    
    '''
    Using SHA1, request from pwnedpasswords.com number of times this 'password' has been pwned. 
    '''
    sha1_password = hashlib.sha1(password.encode(encoding)).hexdigest().upper()
    first5Chars, remainingChars = sha1_password[:5], sha1_password[5:] 
    response = request_api_data(first5Chars)    
    matchCount = get_password_leaks_count(response.text.splitlines(), remainingChars)
    print(f"{password} has been breached {matchCount} times.") 

if __name__ == '__main__':
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            pwned_api_check(password=arg)
    else:
        print("Running in Demo Mode.")
        pwned_api_check(password='password1234')

    
