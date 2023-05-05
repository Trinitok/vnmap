module nmap_xml_result_parser

import walkingdevel.vxml { Node, parse_file }

pub struct NMap {
pub mut:
	scanner string
	version string
	args []string
	scaninfo NMapScanInfoNode
	verbosity NmapVerbosityNode
	debugging NmapDebuggingNode
	host NmapHostNode
	runstats NmapRunStatsNode
}

struct NmapRunStatsNode {
	finish_summary string
	exit_string string
	hosts_up int
	hosts_down int
	total_hosts int
}

struct NMapScanInfoNode {
	scan_type string
	scan_protocol string
	num_services_scanned int
	services_scanned []int
}

struct NmapVerbosityNode {
pub:
	level int
}

struct NmapDebuggingNode {
pub:
	level int
}

struct NmapHostNode {
pub:
	address NMapAddressNode
	hostnames []NMapHostNameNode
	open_ports []NMapPortNode
	os []NMapOSMatchNode
}

struct NMapAddressNode {
	addr string
	addr_type string
}

struct	NMapHostNameNode{
	name string
	host_type string
}

struct NMapPortNode {
	protocol string
	port_id int
	reason string
	reason_ttl int
	service NMapPortServiceNode
	scripts []NMapScriptNode
}

struct NMapOSMatchNode {
	name string
	accuracy int
	line int
	os_classes []NMapOSClassNode
}

struct NMapOSClassNode {
	os_type string
	vendor string
	os_family string
	os_gen string
	accuracy int
	cpe string
}

struct NMapPortServiceNode {
	name string
	product string
	version string
	method string
	confidence int
	cpe string
}

struct NMapScriptNode {
	id string
	output string
}

pub fn parse_nmap_xml_from_file(filename string) NMap {
	nmap_xml := parse_file(filename) or {
		println('There was an error parsing the nmap xml ${filename}')
		panic(err)
	}

	return parse_nmap_xml(nmap_xml)
}

fn parse_nmap_xml(nmap_xml_content Node) NMap {
	mut nmap_struct := NMap {}
	for nmap_child_element in nmap_xml_content.children {
		if nmap_child_element.name == 'nmaprun' {
			nmap_struct.parse_nmaprun_meta(nmap_child_element)
		}
		else {
			println('There was an unknown node at the top level: ${nmap_child_element.name}')
		}
	}

	return nmap_struct
}

fn (mut nmap_instance NMap) parse_nmaprun_meta(nmaprun_meta vxml.Node) {
	scanner := nmaprun_meta.get_attribute('scanner') or {
		panic('The scanner attribute did not exist in this nmaprun node')
	}
	args := nmaprun_meta.get_attribute('args') or {
		panic('The args attribute did not exist in this nmaprun node')
	}
	split_args := args.split(' ')
	version := nmaprun_meta.get_attribute('version') or {
		panic('The version attribute did not exist in this nmaprun node')
	}

	nmap_instance.version = version
	nmap_instance.args = split_args
	nmap_instance.scanner = scanner

	for child_node in nmaprun_meta.children {
		if child_node.name == 'host' {
			nmap_instance.host = parse_host(child_node)
		}
		else if child_node.name == 'verbose' {
			nmap_instance.verbosity = parse_verbosity(child_node)
		}
		else if child_node.name == 'debugging' {
			nmap_instance.debugging = parse_debugging(child_node)
		}
		else if child_node.name == 'scaninfo' {
			nmap_instance.scaninfo = parse_scaninfo(child_node)
		}
		else if child_node.name == 'runstats' {
			nmap_instance.runstats = parse_runstats(child_node)
		}
		else if child_node.name == 'hosthint' {
			parse_hosthint(child_node)
		}
		else {
			println('here is an unexpected nmaprun child element name: ${child_node.name}')
		}
	}
}

fn parse_hosthint(xml_node vxml.Node) {
	// NMap hosthint is currently being omitted at this time

	// println('Here is the hosthint node: ${xml_node}')
}

fn parse_runstats(xml_node vxml.Node) NmapRunStatsNode {
	mut finish_summary := ''
	mut exit_string := ''
	mut hosts_up := 0
	mut hosts_down := 0
	mut total_hosts := 0
	for child_xml_node in xml_node.children {
		if child_xml_node.name == 'finished' {
			finish_summary = child_xml_node.get_attribute('summary') or {
				panic('The summary attribute was not in the runstats finish node')
			}

			exit_string = child_xml_node.get_attribute('exit') or {
				panic('The exit attribute was not in the runstats finish node')
			}
		}
		else if child_xml_node.name == 'hosts' {
			hosts_up_str := child_xml_node.get_attribute('up') or {
				panic('The up attribute was not in the runstats hosts node')
			}
			hosts_up = hosts_up_str.int()
			hosts_down_str := child_xml_node.get_attribute('down') or {
				panic('The down attribute was not in the runstats hosts node')
			}
			hosts_down = hosts_down_str.int()
			total_hosts_str := child_xml_node.get_attribute('total') or {
				panic('The total attribute was not in the runstats hosts node')
			}
			total_hosts = total_hosts_str.int()
		}
		else {
			println('There is an unknown childnode in runstats: ${child_xml_node.name}')
		}
	}

	return NmapRunStatsNode{
		finish_summary: finish_summary
		exit_string: exit_string
		hosts_up: hosts_up
		hosts_down: hosts_down
		total_hosts: total_hosts
	}
}

fn parse_verbosity(verbosity_xml_node vxml.Node) NmapVerbosityNode {
	verbosity_level := verbosity_xml_node.get_attribute('level') or {
		panic('The verbosity level attribute did not exist in this nmap xml output: ${verbosity_xml_node}')
	}
	nmap_verbosity_node := NmapVerbosityNode {
		level: verbosity_level.int()
	}
	return nmap_verbosity_node
}

fn parse_debugging(debugging_xml_node vxml.Node) NmapDebuggingNode {
	debugging_level := debugging_xml_node.get_attribute('level') or {
		panic('The debugging level attribute did not exist in this nmap xml output: ${debugging_xml_node}')
	}
	nmap_debugging_node := NmapDebuggingNode {
		level: debugging_level.int()
	}
	return nmap_debugging_node
}

fn parse_host(host_xml_node vxml.Node) NmapHostNode {
	mut address_node := NMapAddressNode{}
	mut hostnames := []NMapHostNameNode{}
	mut open_ports := []NMapPortNode{}
	mut os_match_list := []NMapOSMatchNode{}
	for child_xml_node in host_xml_node.children {
		if child_xml_node.name == 'address' {
			address_node = parse_host_address_node(child_xml_node)
		}
		else if child_xml_node.name == 'hostnames' {
			hostnames = parse_host_hostnames_node(child_xml_node)
		}
		else if child_xml_node.name == 'ports' {
			open_ports = parse_host_ports_node(child_xml_node)
		}
		else if child_xml_node.name == 'os' {
			os_match_list = parse_host_os_node(child_xml_node)
		}
		else if child_xml_node.name == 'status' {
			parse_host_status_node(child_xml_node)
		}
		else if child_xml_node.name == 'times' {
			parse_host_times_node(child_xml_node)
		}
		else {
			println('Unknown child node in host node: ${child_xml_node.name}')
		}
	}
	host_node := NmapHostNode{
		address: address_node
		hostnames: hostnames
		open_ports: open_ports
		os: os_match_list
	}

	return host_node
}

fn parse_host_status_node(xml_node vxml.Node) {
	// The NMAP host status node just says if a host is up, reason and ttl.
	//  It is currently being omitted since I assume you are up most of the time

	// println('Here is the host status node: ${xml_node}')
}

fn parse_host_times_node(xml_node vxml.Node) {
	// 
	// println('Here is the host times node: ${xml_node}')
}

fn parse_host_os_node(xml_node vxml.Node) []NMapOSMatchNode {
	mut osmatch_node_list := []NMapOSMatchNode{}
	for child_xml_node in xml_node.children {
		if child_xml_node.name == 'osmatch' {
			osmatch_node_list << parse_os_match_node(child_xml_node)
		}
	}
	return osmatch_node_list
}

fn parse_os_match_node(xml_node vxml.Node) NMapOSMatchNode {
	osmatch_name := xml_node.get_attribute('name') or {
		panic('The name attribute did not exist in this osmatch node: ${xml_node}')
	}

	osmatch_accuracy := xml_node.get_attribute('accuracy') or {
		panic('The accuracy attribute did not exist in this osmatch node: ${xml_node}')
	}

	osmatch_line := xml_node.get_attribute('line') or {
		panic('The line attribute did not exist in this osmatch node: ${xml_node}')
	}

	return NMapOSMatchNode{
		name: osmatch_name
		accuracy: osmatch_accuracy.int()
		line: osmatch_line.int()
		os_classes: []
	}
}

fn parse_host_address_node(xml_node vxml.Node) NMapAddressNode {
	target_address := xml_node.get_attribute('addr') or {
		panic('The addr attribute did not exist in this address node: ${xml_node}')
	}
	target_address_type := xml_node.get_attribute('addrtype') or {
		panic('The addrtype attribute did not exist in this address node: ${xml_node}')
	}

	return NMapAddressNode{
		addr: target_address
		addr_type: target_address_type
	}
}

fn parse_host_hostnames_node(xml_node vxml.Node) []NMapHostNameNode {
	mut hostnames := []NMapHostNameNode{}
	for child_xml_node in xml_node.children {
		if child_xml_node.name == 'hostname' {
			host_name := child_xml_node.get_attribute('name') or {
				panic('The name attribute did not exist in this hostname node: ${xml_node}')
			}
			host_type := child_xml_node.get_attribute('type') or {
				panic('The type attribute did not exist in this hostname node: ${xml_node}')
			}

			hostname_node := NMapHostNameNode{
				name: host_name
				host_type: host_type
			}

			hostnames << hostname_node
		}
		else {
			println('Unknown node in hostnames: ${child_xml_node.name}')
		}
	}



	return hostnames
}

fn parse_host_ports_node(xml_node vxml.Node) []NMapPortNode {
	mut open_ports := []NMapPortNode{}
	for child_xml_node in xml_node.children {
		if child_xml_node.name == 'port' {
			open_ports << parse_port_node(child_xml_node)
		}
		// else if child_xml_node.name == 'extraports' {
		// 	open_ports << parse_extraports_node(child_xml_node)
		// }
		else {
			println('Unexpected node in ports: ${child_xml_node.name}')
		}
	}

	return open_ports
}

fn parse_port_node(xml_node vxml.Node) NMapPortNode {
	service_protocol := xml_node.get_attribute('protocol') or {
		panic('The protocol attribute did not exist in this port node: ${xml_node}')
	}

	port_number := xml_node.get_attribute('portid') or {
		panic('The portid attribute did not exist in this port node: ${xml_node}')
	}

	mut reason_for_open := ''
	mut reason_ttl := -1

	mut service_node := NMapPortServiceNode{}
	mut script_nodes := []NMapScriptNode{}

	for child_xml_node in xml_node.children {
		if child_xml_node.name == 'state' {
			reason_for_open = child_xml_node.get_attribute('reason') or {
				panic('The reason attribute did not exist in this port state node: ${xml_node}')
			}
			reason_ttl_str := child_xml_node.get_attribute('reason_ttl') or {
				panic('The reason_ttl attribute did not exist in this port state node: ${xml_node}')
			}
			reason_ttl = reason_ttl_str.int()
		}
		else if child_xml_node.name == 'service' {
			service_node = parse_service_node(child_xml_node)
		}
		else if child_xml_node.name == 'script' {
			script_node := parse_script_node(child_xml_node)
			script_nodes << script_node
		}
		else {
			println('Unknown node in port node: ${child_xml_node.name}')
		}
	}

	return NMapPortNode{
		protocol: service_protocol
		port_id: port_number.int()
		reason: reason_for_open
		reason_ttl: reason_ttl
		service: service_node
		scripts: script_nodes
	}
}

fn parse_service_node(xml_node vxml.Node) NMapPortServiceNode {
	service_name := xml_node.get_attribute('name') or {
		panic('The name attribute did not exist in this port service node: ${xml_node}')
	}

	service_product := xml_node.get_attribute('product') or {
		// TODO: Figure out better way to handle when this is not a version scan
		println('The product attribute did not exist in this port service node: ${xml_node}')
		''
	}

	service_version := xml_node.get_attribute('version') or {
		// TODO: Figure out better way to handle when this is not a version scan
		println('The version attribute did not exist in this port service node: ${xml_node}')
		''
	}

	service_method := xml_node.get_attribute('method') or {
		panic('The method attribute did not exist in this port service node: ${xml_node}')
	}

	mut service_conf_str := xml_node.get_attribute('conf') or {
		panic('The conf attribute did not exist in this port service node: ${xml_node}')
	}

	service_conf := service_conf_str.int()

	return NMapPortServiceNode{
		name: service_name
		product: service_product
		version: service_version
		method: service_method
		confidence: service_conf
		cpe: ''
	}
}

fn parse_script_node(xml_node vxml.Node) NMapScriptNode {
	script_id := xml_node.get_attribute('id') or {
		panic('The id attribute did not exist in this script node: ${xml_node}')
	}

	script_output := xml_node.get_attribute('output') or {
		panic('The output attribute did not exist in this script node: ${xml_node}')
	}

	return NMapScriptNode{
		id: script_id
		output: script_output
	}
}

fn parse_scaninfo(scaninfo_xml_node vxml.Node) NMapScanInfoNode {
	scan_type := scaninfo_xml_node.get_attribute('type') or {
		panic('the scan type was not in the scan info node: ${scaninfo_xml_node}')
	}
	scan_protocol := scaninfo_xml_node.get_attribute('protocol') or {
		panic('the scan protocol was not in the scan info node: ${scaninfo_xml_node}')
	}
	num_services_scanned := scaninfo_xml_node.get_attribute('numservices') or {
		panic('the number of services scanned was not in the scan info node: ${scaninfo_xml_node}')
	}
	services := scaninfo_xml_node.get_attribute('services') or {
		panic('the scan type was not in the scan info node: ${scaninfo_xml_node}')
	}
	split_services_strs_list := services.split(',')
	mut services_arr := []int{}
	for service_num_str in split_services_strs_list {
		if service_num_str.contains('-') {
			split_service_str_interval := service_num_str.split('-')
			start := split_service_str_interval[0].int()
			end := split_service_str_interval[1].int()

			for i := start; i <= end; i ++ {
				services_arr << i
			}
		}
		else {
			services_arr << service_num_str.int()
		}
	}

	scaninfo_node := NMapScanInfoNode{
		scan_type: scan_type
		scan_protocol: scan_protocol
		num_services_scanned: num_services_scanned.int()
		services_scanned: services_arr
	}

	return scaninfo_node
}
