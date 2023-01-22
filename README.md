# What is this?
It is an unofficial wrapper for [NMap](https://nmap.org/) written in [V Lang](https://vlang.io/).  I wrote it to help automate and make some interactions with security capture the flag events more automatable.

# Legal Disclaimer
This is an unofficial wrapper library for NMap.  Any illegal use of this wrapper is not the fault of the person using this library.  Please be sure to obtain all appropriate permissions prior to use.

# Technical
## VLang Version
This was originally made with VLang version 0.3.2.

I assume since the language is still young that things will break at some point. So if things do break please make an issue raising what has broke and I will look into it...when I have time
## NMap Version
This is tested on NMap 7.93 XML output
## XML Parsing in V
I currently use vxml from walkingdevel in order to parse the NMap XML output
- https://vpm.vlang.io/mod/walkingdevel.vxml

# Installation
1. Download and install NMap
1. Install V
    1. https://github.com/vlang/v#installing-v-from-source
1. Install using vpm
> v install Trinitok.v_nmap
4.  In case it is not installed, 

# Verifying
You should be able to run the integration tests which just do a simple scan against `scanme.nmap.org` which is a website authorized by nmap to scan against.

# How to Use
## NMap Runner
This uses a builder pattern in order to run the installed version of nmap.  Below is an example of running nmap using this library
```
import nmap_runner

target_url := 'scanme.nmap.org'
test_output_xml_filename := 'test_full_run.xml'

mut runner := nmap_runner.NMapRunner{}
runner.set_runner_target(target_url)
runner.set_xml_output_name(test_output_xml_filename)
nmap_output := runner.run_nmap_runner()
println(nmap_output.version)
```
This should output the version of nmap on your system.  There are multiple functions which can be used to add to the command arguments being passed to nmap

## NMap XML Parser
This wrapper runner outputs the nmap scan in a local xml file and then attempts to parse it.  The resulting object that is returned will be a parsing of the xml file.

If you have a local xml file for nmap already, you can instead feed that into the parser and it will return an nmap object
```
import nmap_xml_result_parser

nmap_out := nmap_xml_result_parser.parse_nmap_xml_from_file('nmap_out.xml')

println(nmap_out.version)
```

# TODO
1. More NMap functions
    1. I have stealth, version, OS, aggressive, and a few others.  But some more niche or scripts need more builder functions
1. Validate IP input from user
    1. When inputting an IPv4 or IPv6 it currently just takes in a string.  VLang does not provide a good way to validate if the input is structured as an IPv4, IPv6, or jibberish
1. Sanitize nmap script commands from user
    1. Same as above for IP sanitation and validation except for nmap scripts
1. Better parsing for different NMap commands
    1. I have only tested with certain commands since I am doing CTFs
1. Option to keep the xml file after using the runner