#!/usr/bin/env python
# coding: utf-8
#
# By Leon Johnson - twitter.com/sho_luv
#
# This program I wrote with the help of chatGPT
# to extract the ssids and key information from android devices


import argparse
import subprocess
import importlib.util
import xml.etree.ElementTree as ET

rich_installed = importlib.util.find_spec('rich') is not None

if rich_installed:
    from rich.console import Console
    from rich.table import Table
    console = Console()
else:
    console = None

def adb_pull_wifi_config():
    command = "adb shell cat /data/misc/wifi/WifiConfigStore.xml"
    try:
        result = subprocess.run(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        console.print(f"An error occurred: {e.stderr}", style="bold red")
        return None


def parse_wifi_data(file_data):
    root = ET.fromstring(file_data)

    wifi_data = []

    for network in root.findall(".//Network"):
        wifi_config = network.find("WifiConfiguration")
        if wifi_config is not None:
            config_key = wifi_config.find("string[@name='ConfigKey']").text.strip('"')
            ssid = wifi_config.find("string[@name='SSID']").text.strip('"')
            pre_shared_key_element = wifi_config.find("string[@name='PreSharedKey']")
            pre_shared_key = pre_shared_key_element.text.strip('"') if pre_shared_key_element is not None else None
            network_type = config_key.split('"')[-1]

            if pre_shared_key is not None:
                wifi_data.append((network_type, ssid, pre_shared_key))

    return wifi_data


def print_wifi_data(wifi_data):
    if rich_installed:
        table = Table(title="ChatGPT has won...", title_style="bold magenta")
        table.add_column("Type", style="cyan")
        table.add_column("SSID", style="green")
        table.add_column("Key", style="yellow")

        for network_type, ssid, pre_shared_key in wifi_data:
            table.add_row(network_type, ssid, pre_shared_key)

        console.print(table)
    else:
        max_type_length = max(len(network_type) for network_type, _, _ in wifi_data)
        max_ssid_length = max(len(ssid) for _, ssid, _ in wifi_data)
        max_key_length = max(len(pre_shared_key) for _, _, pre_shared_key in wifi_data)

        print()
        print("ChatGPT has won...")
        print()
        print(f"| {'-' * (max_type_length)} | {'-' * (max_ssid_length)} | {'-' * (max_key_length)} |")
        print(f"| {'Type:': <{max_type_length}} | {'SSID:': <{max_ssid_length}} | {'Key:': <{max_key_length}} |")
        print(f"| {'-' * (max_type_length)} | {'-' * (max_ssid_length)} | {'-' * (max_key_length)} |")

        for network_type, ssid, pre_shared_key in wifi_data:
                print(f"| {network_type: <{max_type_length}} | {ssid: <{max_ssid_length}} | {pre_shared_key: <{max_key_length}} |")

        print(f"| {'-' * (max_type_length)} | {'-' * (max_ssid_length)} | {'-' * (max_key_length)} |")
        print()




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract Wi-Fi information from an XML file or device")
    parser.add_argument("-f", "--file", type=str, help="Path to the XML file")
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r") as file:
            file_data = file.read()
    else:
        file_data = adb_pull_wifi_config()

    if file_data is not None:
        wifi_data = parse_wifi_data(file_data)
        print_wifi_data(wifi_data)
    else:
        console.print("Failed to retrieve Wi-Fi data.", style="bold red")

