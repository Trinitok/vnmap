module test

import nmap_runner

fn test_scanning_url_and_parsing_output() {
	target_url := 'scanme.nmap.org'
	test_output_xml_filename := 'test_full_run.xml'

	mut runner := nmap_runner.NMapRunner{}
	runner.set_runner_target(target_url)
	runner.set_xml_output_name(test_output_xml_filename)
	nmap_output := runner.run_nmap_runner()
	println(nmap_output.version)
}

fn test_scanning_url_with_ports() {
	target_url := 'scanme.nmap.org'
	test_output_xml_filename := 'test_full_run.xml'
	test_ports := [80,443,8080]

	mut runner := nmap_runner.NMapRunner{}
	runner.set_runner_target(target_url)
	runner.set_ports(test_ports)
	runner.set_xml_output_name(test_output_xml_filename)
	nmap_output := runner.run_nmap_runner()
	println(nmap_output.version)
}