module nmap_runner

import os
import nmap_xml_result_parser

// The Runner wrapper for nmap.  Make sure you have nmap installed
// Follows a builder pattern so you will need to construct the commands
//  by calling the individual functions below
// When finalized, please call the run_nmap() function for this struct
pub struct NMapRunner {
mut:
	target string
	ports []int
	command string
	xml_output_filename string
	delete_xml_after_run bool = false
}

pub fn (runner NMapRunner) get_runner_target() string {
	return runner.target
}

pub fn (runner NMapRunner) get_ports() []int {
	return runner.ports
}

pub fn (runner NMapRunner) get_command_string() string {
	return runner.command
}

pub fn (runner NMapRunner) get_xml_filename() string {
	return runner.xml_output_filename
}

pub fn (runner NMapRunner) get_delete_xml_after_run() bool {
	return runner.delete_xml_after_run
}

pub fn (mut runner NMapRunner) set_delete_xml_after_run(option bool) {
	runner.delete_xml_after_run = option
}

//  WARNING: Does not validate the IP is in the correct format
//  This could open up to other issues.
//  Currently VLang does not have a good way to check if the IP
//  is a valid format.  Although it seems like some code is slotted
//  to be done eventually
//  https://github.com/vlang/v/blob/017ace6ea7402430a992aa0820d5e472ebca74c7/vlib/net/http/cookie.v#L239
//
//
//  This could lead to issues such as command injection, but I assume
//  that if the attacker was able to inject commands into this, you have
//  bigger problems
pub fn (mut runner NMapRunner) set_runner_target(target string) {
	runner.target = target
}

// -oX <xml_filename>
pub fn (mut runner NMapRunner) set_xml_output_name(xml_filename string) {
	runner.xml_output_filename = xml_filename
}

// adds -sS
pub fn (mut runner NMapRunner) add_stealth_scan_flag() {
	runner.command = runner.command + ' -sS'
}

// adds -O
pub fn (mut runner NMapRunner) add_os_scan_flag() {
	runner.command = runner.command + ' -O'
}

// adds -A
pub fn (mut runner NMapRunner) add_agressive_scan_flag() {
	runner.command = runner.command + ' -A'
}

// adds -sV
pub fn (mut runner NMapRunner) add_version_scan_flag() {
	runner.command = runner.command + ' -sV'
}

// adds -sn
pub fn (mut runner NMapRunner) add_ping_scan_flag() {
	runner.command = runner.command + ' -sn'
}

// adds -sU
pub fn (mut runner NMapRunner) add_udp_scan_flag() {
	runner.command = runner.command + ' -sU'
}

// adds -sN
pub fn (mut runner NMapRunner) add_tcp_null_scan_flag() {
	runner.command = runner.command + ' -sN'
}

// adds -sX
pub fn (mut runner NMapRunner) add_xmas_scan_flag() {
	runner.command = runner.command + ' -sX'
}

// adds -sF
pub fn (mut runner NMapRunner) add_tcp_fin_scan_flag() {
	runner.command = runner.command + ' -sF'
}

// adds -sC
pub fn (mut runner NMapRunner) add_script_scan_flag() {
	// TODO
}

// adds -Pn
pub fn (mut runner NMapRunner) assume_hosts_online() {
	runner.command = runner.command + ' -Pn'
}

// adds -v
pub fn (mut runner NMapRunner) increase_verbosity(level int) {
	// TODO
}

// adds -d
pub fn (mut runner NMapRunner) increase_debugging(level int) {
	// TODO
}

// Checks to see if the port, p, is 0 < p < 65535
fn validate_port(port int) bool {
	return port > 0 && port < 65535
}

// Loops over every integer and passes them to validate_port
// if something is invalid, it will immediately return false
// else it returns true
fn validate_ports(ports []int) bool {
	for port in ports {
		valid := validate_port(port)
		if !valid {
			return false
		}
	}

	return true
}

// sets the value for the -p flag.  Each will be comma separated in the CLI
// -p <ports>
pub fn (mut runner NMapRunner) set_ports(ports []int) {
	valid_port_range := validate_ports(ports)
	if valid_port_range {
		runner.ports = ports
	}
	else {
		panic('The port range entered was invalid')
	}
}

fn (runner NMapRunner) convert_port_vals_to_strings() string {
	mut ret_str := ''
	for i := 0; i < runner.ports.len; i ++ {
		port := runner.ports[i]
		ret_str = ret_str + port.str()

		if i != runner.ports.len - 1 {
			ret_str = ret_str + ','
		}
	}
	return ret_str
}

// runs the full nmap command based on what was specified using the runner struct
pub fn (mut runner NMapRunner) run_nmap_runner() nmap_xml_result_parser.NMap {
	command_prefix := 'sudo nmap ' // I always assume you will need sudo
	xml_output_flag := ' -oX ' + runner.xml_output_filename
	mut ports_string := ''

	if runner.ports.len > 0 {
		ports_string = ' -p ' + runner.convert_port_vals_to_strings()
	}

	full_command := command_prefix + runner.target + ports_string + runner.command + xml_output_flag

	println('VLang NMap Runner is executing the following with nmap: ${full_command}')

	os.execute_or_panic(full_command)

	parsed_nmap_output := nmap_xml_result_parser.parse_nmap_xml_from_file(runner.xml_output_filename)

	if runner.delete_xml_after_run {
		os.rm(runner.xml_output_filename) or {
			println('there was an error attempting to remove the nmap xml file ${runner.xml_output_filename}')
		}
	}

	return parsed_nmap_output
}

// Will run nmap using whatever commands you choose to pass
//  will automatically append the -oX flag along with a filename
//  will then parse the file output and return an NMap struct
pub fn run_nmap_command_adhoc(nmap_command string) nmap_xml_result_parser.NMap {
	sample_xml_out_filename := 'adhoc_nmap_run.xml'

	full_command := 'sudo nmap ' + nmap_command + ' -oX ${sample_xml_out_filename}'

	os.execute_or_panic(full_command)

	return nmap_xml_result_parser.parse_nmap_xml_from_file(sample_xml_out_filename)	

}