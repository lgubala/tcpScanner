import click
import json
import ipaddress
from socket import AF_INET
from socket import SOCK_STREAM
from socket import SOCK_DGRAM
from socket import socket
from concurrent.futures import ThreadPoolExecutor

scansFile = "scans.json"
lastScans = {}


@click.command()
@click.argument('ipadress')
@click.option('--s', 'start', default=1, show_default=True, help='starting port of scan')
@click.option('--e', 'end', default=500, show_default=True, help='ending port of scan')

def main(ipadress,start,end):
    """A simple network scans that displays differences between scans.

	IPADRESS IP Address of the target (e.g. 192.168.1.1) or network range
	(e.g. 192.168.1.1/17)
	"""

    ports = range(start ,end)
    scans = {}
    try:
        ip_to_scan = ipaddress.ip_network(ipadress).hosts()
    except:
        exit_with_msg()

    try:
        with open(scansFile, "r") as file:
            scans = json.load(file)
    except IOError:
        pass

    for address in ip_to_scan:
        scan_ports_tcp(address, ports)
    compare_scans(scans, lastScans)


def scan_ports_tcp(host, ports):
    with ThreadPoolExecutor(len(ports)) as executor:
        results = executor.map(test_port_tcp, [host] * len(ports), ports)
        for port, is_open in zip(ports, results):
            if is_open:
                if "tcp" in lastScans:
                    if host not in lastScans["tcp"]:
                        lastScans["tcp"].update({host: {"ports": []}})
                        lastScans["tcp"][host]["ports"].append(port)
                    else:
                        lastScans["tcp"][host]["ports"].append(port)
                else:
                    lastScans.update({"tcp": {host: {"ports": []}}})
                    lastScans["tcp"][host]["ports"].append(port)


def test_port_tcp(host, port):
    # address type IPv4, socket type TPC
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.settimeout(3)
        try:
            sock.connect((host, port))
            # port is open
            return True
        except:
            return False


def compare_scans(scans, last_scans):
    dif_scans = {
        "open": {
        },
        "closed": {

        }
    }
    if len(scans) > 0:
        if len(last_scans) > 0:
            if last_scans == scans:
                print("No differences found between scans.")
            else:
                for address in last_scans["tcp"]:
                    if address in scans["tcp"]:
                        for port in last_scans["tcp"][address]["ports"]:
                            if port not in scans["tcp"][address]["ports"]:
                                if address not in dif_scans["open"]:
                                    dif_scans["open"][address] = {"ports": []}
                                    dif_scans["open"][address]["ports"].append(port)
                                else:
                                    dif_scans["open"][address]["ports"].append(port)
                    else:
                        for port in last_scans["tcp"][address]["ports"]:
                            if address not in dif_scans["open"]:
                                dif_scans["open"][address] = {"ports": []}
                                dif_scans["open"][address]["ports"].append(port)
                            else:
                                dif_scans["open"][address]["ports"].append(port)
                for ip in scans["tcp"]:
                    if ip in last_scans["tcp"]:
                        for port in scans["tcp"][ip]["ports"]:
                            if port not in last_scans["tcp"][ip]["ports"]:
                                if ip not in dif_scans["closed"]:
                                    dif_scans["closed"][ip] = {"ports": []}
                                    dif_scans["closed"][ip]["ports"].append(port)
                                else:
                                    dif_scans["closed"][ip]["ports"].append(port)
                    else:
                        for port in scans["tcp"][ip]["ports"]:
                            if ip not in dif_scans["closed"]:
                                dif_scans["closed"][ip] = {"ports": []}
                                dif_scans["closed"][ip]["ports"].append(port)
                            else:
                                dif_scans["closed"][ip]["ports"].append(port)
        else:
            for address in scans["tcp"]:
                for port in scans["tcp"][address]["ports"]:
                    if address not in dif_scans["closed"]:
                        dif_scans["closed"][address] = {"ports": []}
                        dif_scans["closed"][address]["ports"].append(port)
                    else:
                        dif_scans["closed"][address]["ports"].append(port)
    else:
        if len(last_scans) > 0:
            for address in last_scans["tcp"]:
                print(address)
                for port in last_scans["tcp"][address]["ports"]:
                    if address not in dif_scans["open"]:
                        dif_scans["open"][address] = {"ports": []}
                        dif_scans["open"][address]["ports"].append(port)
                    else:
                        dif_scans["open"][address]["ports"].append(port)
        else:
            print("No open ports found in this or previous scan !")

    for item in dif_scans["open"]:
        print(f"{item}")
        for port in dif_scans["open"][item]["ports"]:
            print(f"* {port}/tcp open")
    for item in dif_scans["closed"]:
        print(f"{item}")
        for port in dif_scans["closed"][item]["ports"]:
            print(f"* {port}/tcp closed")

    with open(scansFile, "w") as file:
        json.dump(last_scans, file)


def exit_with_msg():
    ctx = click.get_current_context()
    ctx.fail("Invalid address or network")


if __name__ == '__main__':
    main()
