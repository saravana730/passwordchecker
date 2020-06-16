import requests 
import hashlib
import sys
'''
program to check your password strength 
using pwned API from https://haveibeenpwned.com/ website
by reading text file with passwords

'''

def request_api_data(query_char):    #function to get api response
  url = 'https://api.pwnedpasswords.com/range/' + query_char
  res = requests.get(url)
  if res.status_code != 200:
    raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
  return res


def get_password_leaks_count(hashes, hash_to_check): #function to count number of times password is leaked
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0

def pwned_api_check(password):  #function to hash  first five characters of our password using sha1 algorithm
    sha1password = (hashlib.sha1(password.encode('utf-8')).hexdigest().upper())
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    
    return get_password_leaks_count(response,tail)


def main(data): #a function to read password 
	for password in data:
		count = pwned_api_check(password)
		if count:
			print(f'{password} was found this times {count} you should change')
		else:
		  print(f'{password} was not found good to go')	
 


data = open('''pass in text file with passwords''','r')  

main(data)