#!/usr/bin/python3

import argparse
import pathlib
import sys
import json
import requests
import time

BANNER = """


  ████████╗ █████╗ ████████╗ █████╗ ███╗   ███╗██╗
  ╚══██╔══╝██╔══██╗╚══██╔══╝██╔══██╗████╗ ████║██║
     ██║   ███████║   ██║   ███████║██╔████╔██║██║
     ██║   ██╔══██║   ██║   ██╔══██║██║╚██╔╝██║██║
     ██║   ██║  ██║   ██║   ██║  ██║██║ ╚═╝ ██║██║
     ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝
                                                
Developed by Oriel & Spopy
github.com/OrielOrielOriel
github.com/sq00ky

Note: For tab delimiting to function properly when pasted to Excel. Output must be redirected or tee'd into a file then copied from there. Do not copy from the terminal.
"""

#  Defines path as the parent directory of the script + the character '/'
PATH = str(pathlib.Path(__file__).parent.absolute()) + '/'

def parseArguments():
	parser = argparse.ArgumentParser(description=BANNER, formatter_class=argparse.RawTextHelpFormatter)

	parser.add_argument('-a', '--api-key',
		metavar='api_key',
		type=str,
		help='The Shodan API key.'
	)

	parser.add_argument('-t', '--target',
		metavar='target',
		type=str,
		help='The IP address of the target. Use -tf to specify a file containing a list of targets.'
	)

	parser.add_argument('-tf', '--target-file',
		metavar='target_file',
		type=str,
		help='A file containing a newline delimited list of target IPs. Use -t to specify a single target.'
	)

	parser.add_argument('-o', '--options',
		metavar='options',
		type=str,
		action='extend',
		nargs='+',
		help='Data to be retrieved. Common fields ip_str=Host IP address, hostnames=Host name, port=Open ports, product=Product version on the particular port, banner=Banner from a connection to the port. date=Current date.'
	)

	return parser

"""
Returns a list of targets from a file where
each line is considered a separate target. 

Lines which are blank or start with a '#'
are ignored.
""" 
def loadTargets(parserMetavar):
	if parserMetavar is None: return []
	with open(parserMetavar, "r") as all_targets:
		return [target.rstrip().split() for target in all_targets.readlines() if target.strip() and not target.startswith("#")]


"""
Iterates over a list of targets and performs
a get request to Shodan's /host/{ip} endpoint
where {ip} is the target.

Uses the API key provided by -a / --api-key.

Yields the text reponse received from the get
request.
"""   
def getHostInfo(api_key, targets):
	for target in targets:
		yield requests.get(f'https://api.shodan.io/shodan/host/{target[0]}?key={api_key}').text


"""
Accepts a dictionary via 'dataset' and a 
list via 'options'

Each object in the list will be used as a key
for the dictionary 'dataset.' 

Yields the value 
associated with the key if that key is present
and has content associated with it, else it 
yields "N/A"
"""
def yieldData(dataset: dict, options: list):
	for option in options:
		try:
			if option == "date":
				current_date = time.strftime(r"%m/%d/%Y")
				yield str(current_date)

			if option == "hostnames":
				if dataset[option]:
					yield str(dataset[option][0])

				else:
					yield "N/A"

			else:
				yield str(dataset[option])

		except KeyError:
			if option == "date":
				pass
			else:
				yield "N/A"

def main():
	parser = parseArguments() 

	# If no CLI arguments are provided, print the argparse help screen. 
	if len(sys.argv)==1:
		parser.print_help(sys.stderr)
		sys.exit(1)

	parser = parser.parse_args()

	if not (parser.target or parser.target_file):
		raise Exception('No target or target file provided.')

	targets = [parser.target] if parser.target else loadTargets(parser.target_file)
	results = [result for result in getHostInfo(parser.api_key, targets)]

	# Iterates over each API result
	for result in results:
		jsonobj = json.loads(result)  # Loads the result as a json object.

		try:

			# Iterates over each dictionary in the 
			# primary "data" field. 
			for dataset in jsonobj["data"]:
				# Joins each object in the list with a "\t" (tab).
				row = "\t".join(
					# Creates a list of the string objects yielded by yieldData()
					[datapoint for datapoint in yieldData(dataset, parser.options)]
				)

				print(row)

		except KeyError:
			pass
			# No open ports found.
			

if __name__ == '__main__':
	main()
