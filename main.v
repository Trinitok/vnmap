module main

import nmap_runner

fn main() {
	mut runner := nmap_runner.NMapRunner{}
	runner.set_runner_target('10.30.15.5')
	runner.set_xml_output_name('test_full_run.xml')
	ports := [80,443,8080]
	runner.set_ports(ports)
	nmap_struct := runner.run_nmap_runner()
	println(nmap_struct.version)
}
