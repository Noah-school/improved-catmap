import asyncio
import ipaddress
import logging
import subprocess
import time
import nmap
import json
import click
from PIL import Image
from lib.display import initialize_display, update_display

logging.basicConfig(
    filename="./output/errors.log",
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


async def pingda(emulate, ip, wait, count, callback=None):
    try:
        if emulate:
            process = await asyncio.create_subprocess_exec(
                "ping",
                "-n",
                str(count),
                "-w",
                str(wait * 1000),
                str(ip),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        else:
            process = await asyncio.create_subprocess_exec(
                "ping",
                "-c",
                str(count),
                "-W",
                str(wait),
                str(ip),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        stdout, _ = await process.communicate()
        if "Request timed out." not in stdout.decode() and "Destination Host Unreachable" not in stdout.decode():
            if callback:
                callback(ip, "Ping scan")
            return ip
    except Exception as e:
        logging.error(f"Error in pingda: {e}")
    return None


async def pingscan(emulate, network, wait=1, count=4, callback=None):
    try:
        subnet = ipaddress.IPv4Network(network)
        upHosts = []
        hosts = [str(ip) for ip in subnet.hosts()]

        tasks = [pingda(emulate, ip, wait, count, callback) for ip in hosts]
        initialResults = await asyncio.gather(*tasks)
        upHosts.extend(filter(None, initialResults))
        return upHosts
    except Exception as e:
        logging.error(f"Error in pingscan: {e}")
        return []


async def nmapScan(host, args, callback=None):
    try:
        nm = nmap.PortScanner()
        scanResult = await asyncio.to_thread(nm.scan, hosts=host, arguments=args)
        if callback:
            callback(scanResult, "Nmap scan")
        return host, scanResult
    except Exception as e:
        logging.error(f"Error in nmap_scan: {e}")
        return host, {}


async def async_nmap_DataScan(upHosts, callback=None):
    try:
        args = "-T4 -A"
        scan_results = {}
        with open("./output/scan_results.json", "w") as f:
            for host in upHosts:
                host, result = await nmapScan(host, args, callback)
                scan_results[host] = result
                f.seek(0)
                json.dump(scan_results, f, indent=4)
                f.truncate()
        return scan_results
    except Exception as e:
        logging.error(f"Error in async_nmap_DataScan: {e}")
        return {}


def filterScanResults(scan_results):
    try:
        filtered_results = {}
        for ip, data in scan_results.items():
            open_ports = [
                {
                    "port": port,
                    "service": details["name"],
                    "product": details.get("product", ""),
                    "version": details.get("version", ""),
                }
                for port, details in data["scan"][ip].get("tcp", {}).items()
                if details["state"] == "open"
            ]

            filtered_results[ip] = {
                "hostnames": data["scan"][ip].get("hostnames", []),
                "vendor": data["scan"][ip].get("vendor", {}),
                "os": [
                    {"name": osmatch["name"], "accuracy": osmatch["accuracy"]}
                    for osmatch in data["scan"][ip].get("osmatch", [])
                ],
                "open_ports": open_ports,
            }
        return filtered_results
    except Exception as e:
        logging.error(f"Error in filter_scan_results: {e}")
        return {}


def showConsoleOutput(filtered_HostPorts):
    try:
        for ip, data in filtered_HostPorts.items():
            print("-" * 20)
            print(f"IP: {ip}")
            if data["hostnames"] and data["hostnames"][0]["name"] != "":
                print(f"Host: {data['hostnames'][0]['name']}")
            if data["vendor"]:
                print(f"Vendor: {list(data['vendor'].values())[0]}")
            if data["os"]:
                print(f"OS: {data['os'][0]['name']}")
            if data["open_ports"]:
                print(
                    f"Ports: {', '.join(str(port['port']) for port in data['open_ports'])}"
                )
    except Exception as e:
        logging.error(f"Error in show_console_output: {e}")


@click.command()
@click.option(
    "--emulate",
    "-e",
    is_flag=True,
    default=False,
    help="Simulate the display (no hardware required)",
)
@click.option(
    "--network",
    "-n",
    default="192.168.0.0/24",
    show_default=True,
    help="Network range to scan",
)
@click.option(
    "--noscan",
    "-ns",
    is_flag=True,
    default=False,
    help="Simulate scan results from file",
)
def main(emulate, network, noscan):
    try:
        epd = initialize_display(emulate=emulate)
        image = Image.new("1", (epd.width, epd.height), 0).tobytes()
        text = [
            {
                "text": "{0:=^20}".format("| {0} |".format("cybercat")),
                "position": (epd.width // 2 - 52, 8),
                "font_size": 10,
            },
        ]
        update_display(
            epd,
            image,
            text
            + [
                {
                    "text": "Network Scanner",
                    "position": (epd.width // 2 - 46, 22),
                    "font_size": 12,
                }
            ],
            full_refresh=True,
        )

        backlog = []

        def displayCallback(result, scan_type="Unknown"):
            try:
                if scan_type == "Ping scan":
                    ip = result
                    backlog.append({"ip": ip, "vendor": ""})
                    if len(backlog) > 17:
                        backlog.pop(0)
                    text_backlog = text.copy() + [
                        {
                            "text": scan_type,
                            "position": (epd.width // 2 - 28, 22),
                            "font_size": 12,
                        }
                    ]
                    for i, entry in enumerate(reversed(backlog)):
                        text_backlog.append(
                            {
                                "text": entry["ip"],
                                "position": (epd.width // 2 - 36, 36 + i * 12),
                                "font_size": 10,
                            }
                        )
                elif scan_type == "Nmap scan":
                    scan_result = result
                    if scan_result["scan"]:
                        ip = list(scan_result["scan"].keys())[0]
                        vendor = (
                            list(scan_result["scan"][ip].get("vendor", {}).values())[0]
                            if scan_result["scan"][ip].get("vendor")
                            else ""
                        )
                        backlog.append({"ip": ip, "vendor": vendor})
                        if len(backlog) > 7:
                            backlog.pop(0)
                        text_backlog = text.copy() + [
                            {
                                "text": scan_type,
                                "position": (epd.width // 2 - 28, 22),
                                "font_size": 12,
                            }
                        ]
                        for i, entry in enumerate(reversed(backlog)):
                            text_backlog.append(
                                {
                                    "text": entry["ip"],
                                    "position": (6, 36 + i * 30),
                                    "font_size": 10,
                                }
                            )
                            text_backlog.append(
                                {
                                    "text": (
                                        entry["vendor"]
                                        if entry["vendor"]
                                        else "Unknown"
                                    ),
                                    "position": (6, 48 + i * 30),
                                    "font_size": 10,
                                }
                            )
                if 'text_backlog' in locals():
                    update_display(epd, image, text_backlog)
                time.sleep(0.1)
            except Exception as e:
                logging.error(f"Error in display_callback: {e}")

        if noscan:
            with open("./output/scan_results.json", "r") as f:
                HostPorts = json.load(f)
        else:
            upHosts = asyncio.run(pingscan(emulate, network, callback=displayCallback))
            print("Total up hosts count:", len(upHosts))

            backlog.clear()

            update_display(
                epd,
                image,
                text
                + [
                    {
                        "text": "Starting Nmap scan...",
                        "position": (epd.width // 2 - 54, 22),
                        "font_size": 12,
                    }
                ],
            )

            HostPorts = asyncio.run(
                async_nmap_DataScan(upHosts, callback=displayCallback)
            )

        update_display(
            epd,
            image,
            text
            + [
                {
                    "text": "Network Scanner",
                    "position": (epd.width // 2 - 46, 22),
                    "font_size": 12,
                },
                {
                    "text": "Scan complete",
                    "position": (epd.width // 2 - 40, 32),
                    "font_size": 12,
                },
            ],
        )

        filtered_HostPorts = filterScanResults(HostPorts)
        showConsoleOutput(filtered_HostPorts)
    except KeyboardInterrupt:
        print("Process interrupted by user")
    except Exception as e:
        logging.error(f"Error in main: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Process interrupted by user")
    except Exception as e:
        logging.error(f"Error in __main__: {e}")
