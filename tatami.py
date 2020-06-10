#!/usr/bin/python3

import argparse
import pathlib
import sys
import tablib
import json
import requests
import csv
import pandas
import time

BANNER = """
Sup
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

	parser.add_argument('-o', '--output',
		metavar='outfile',
		type=str,
		help='The filename to output to.'
	)

	return parser


def loadTargets(parserMetavar):
	if parserMetavar is None: return []
	with open(parserMetavar, "r") as all_targets:
		return [target.rstrip().split() for target in all_targets.readlines() if target.strip() and not target.startswith("#")]


def getHostInfo(api_key, targets):

	for target in targets:
		yield requests.get(f'https://api.shodan.io/shodan/host/{target}?key={api_key}').text


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
	results = results[0]
	jsonobj = json.loads(results)
	current_time = time.strftime(r"%m/%d/%Y")
	openports = jsonobj["ports"]
	for i in openports:
		print(jsonobj["ip_str"], "\t", jsonobj["hostnames"], "\t", jsonobj["os"], "\t", jsonobj["data"][0]["transport"], "\t", i, "\t\t", current_time, "\t Shodan\tPassive")

if __name__ == '__main__':
	main()
