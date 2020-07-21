# tatami
Shodan API tool.

```
usage: tatami.py [-h] [-a api_key] [-t target] [-tf target_file] [-o options [options ...]]

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

optional arguments:
  -h, --help            show this help message and exit
  -a api_key, --api-key api_key
                        The Shodan API key.
  -t target, --target target
                        The IP address of the target. Use -tf to specify a file containing a list of targets.
  -tf target_file, --target-file target_file
                        A file containing a newline delimited list of target IPs. Use -t to specify a single target.
  -o options [options ...], --options options [options ...]
                        Data to be retrieved. Common fields ip_str=Host IP address, hostnames=Host name, port=Open ports, product=Product version on the particular port, banner=Banner from a connection to the port. date=Current date.
```

## Examples
```
> cat targets.txt 

8.8.8.8
54.244.153.152
2001:4860:4860::8844

> ./tatami.py -a $API -tf targets.txt -o ip_str hostnames product info port

8.8.8.8	dns.google	N/A	N/A	53
54.244.153.152	ec2-54-244-153-152.us-west-2.compute.amazonaws.com	Minecraft	N/A	25565
2001:4860:4860::8844	dns.google	N/A	N/A	53
2001:4860:4860::8844	dns.google	N/A	N/A	443
2001:4860:4860::8844	dns.google	N/A	N/A	53

> ./tatami.py -a $API -tf targets.txt -o ip_str hostnames product info port > out.txt
```

In the text above you can see that tatami is retrieving data for 3 IPs, it is retrieving the fields: ip_str, hostnames, product, info, port. When it cannot find data for a given field, it puts in "N/A." The different fields are tab delimited and can therefore be easily pasted into a spreadsheet. The final command begins this process by redirecting the output into a file to be easily copied. The following images show the copying of the data, and then the pasting of the data into a spreadsheet. 

![Copying output from a text file](/.photos/copying.png)

![Pasting output into a spreadsheet. Each field goes into a separate cell](/.photos/pasted.png)
