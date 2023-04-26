#!/usr/bin/env python3

import argparse
import json
import hashlib
from os import PathLike

import cbor2
from tempfile import NamedTemporaryFile
import asyncio

import sys
import pkg_resources

from fort_cli_cfg.fast import get_device_config_from_fm, get_user_credentials, login
from fort_cli_cfg.fast import FmResponseException
from fort_cli_cfg.validators import get_data_formatter, get_data_formatter_types

from . import coap

if sys.version_info >= (3, 8):
    from importlib import metadata
else:
    import importlib_metadata as metadata

from serial import Serial, SerialException

from fort_cli_cfg.serial_udp_bridge import SingleClientSerialUdpBridge
from fort_cli_cfg.core import build_endpoint, progress_bar


# read version from package metadata (see pyproject.toml)
__version__ = metadata.version(__package__ or __name__)


from enum import Enum


default_web_path = "https://api.fortrobotics.com/"


class NXPEndpoints(str, Enum):
    SINGLE_CONFIG = "cfg/all"
    DEV_FW = "fl/updateAppImg"

    BLE_FW = "fl/radiofw"
    BLE_FW_INFO = "cfg/radiofw/expectedCrc"

    ISM_FW = "fl/ismfw"
    ISM_FW_INFO = "cfg/ismfw/expectedCrc"
    SYSTEM_RESET = "cfg/setup/systemReset"


class EPCEndpoints(str, Enum):
    SINGLE_CONFIG = "cfg/all"
    DEV_FW = "fl/fw/epc"
    ISM_FW = "fl/fw/ism/reflash"
    SYSTEM_RESET = "cfg/setup/systemReset"


Endpoints = NXPEndpoints


class TargetDevice(Enum):
    NXP = 0
    EPC = 1


TARGET_DEVICE = None


def generate_secure_config_cbor(config_json: dict, output_secure_config: PathLike):
    data = cbor2.encoder.dumps(config_json)
    shaStr = hashlib.sha256(data).hexdigest()
    with open(output_secure_config, "wb") as f:
        secure_config = {
            "config-data": data,
            "config-checksum": shaStr,
            "r-component": "DummyRComponent",
            "s-component": "DummySComponent",
            "fso7-3": "DummyFSO7_3PEM"
        }
        cbor2.dump(secure_config, f)
    return secure_config


async def device_get_file(coap_ip_addr: str, ep_uri: str, outfile_path=""):
    if not outfile_path:
        outfile_path = ep_uri.replace("/", "_") + ".bin"
    print(f"Get file from {ep_uri} to {outfile_path}")
    with progress_bar() as progress:
        return await coap.get_file(coap_ip_addr, ep_uri, outfile_path, progress)


async def device_get_file_crc(coap_ip_addr: str, ep_uri: str):
    return await device_exec_get_generic(coap_ip_addr, f"coap:int:{ep_uri}/crc")


async def device_post_file(coap_ip_addr: str, endpoint: str, filepath: PathLike, target_filename=""):
    if TARGET_DEVICE == TargetDevice.NXP:
        with progress_bar() as progress:
            return await coap.post_file(coap_ip_addr, f"{endpoint}/data", f"{endpoint}/metadata", filepath,
                                        target_filename, progress)
    elif TARGET_DEVICE == TargetDevice.EPC:
        with open(filepath, "rb") as f:
            data = f.read()
            shaStr = hashlib.sha256(data).hexdigest()
            payload = {"length": len(data), "data": data, "sha256": shaStr}
            return await coap.post_cbor(coap_ip_addr, endpoint, payload=payload)
    else:
        raise RuntimeError("Target device not specified")


async def device_post_single_config(coap_ip_addr: str, single_config: dict):
    with NamedTemporaryFile(suffix=".cbor", delete=False) as named_tempfile:
        cbor2.dump(single_config, named_tempfile)
        temp_cbor_filepath = named_tempfile.name

    print(f"Pushing single-config file {temp_cbor_filepath} to {coap_ip_addr}")
    if TARGET_DEVICE == TargetDevice.NXP:
        return await device_post_file(coap_ip_addr, Endpoints.SINGLE_CONFIG, temp_cbor_filepath)
    elif TARGET_DEVICE == TargetDevice.EPC:
        secure_config = generate_secure_config_cbor(single_config, temp_cbor_filepath)
        return await coap.post_cbor(coap_ip_addr, Endpoints.SINGLE_CONFIG, secure_config)
    else:
        raise RuntimeError("Target device not specified")


async def device_get_single_config(coap_ip_addr: str):
    crc = await device_get_file_crc(coap_ip_addr, Endpoints.SINGLE_CONFIG)
    filename = f"singleConfig_{crc}.cbor"
    await device_get_file(coap_ip_addr, Endpoints.SINGLE_CONFIG, filename)
    with open(filename, "r") as cborfile:
        json.dump(cbor2.load(cborfile), filename)
        print(f"Retrieved single config - see {filename} for contents")


async def device_exec_get_generic(coap_ip_addr: str, target: str):
    tokens = target.split(":")
    allowed_types = [*get_data_formatter_types(), "file", "blockwise"]

    if len(tokens) != 3 or tokens[0] != "coap" or tokens[1] not in allowed_types:
        print("Generic GET syntax: coap:<type>:/manual/endpoint/path")
        print("Generic GET syntax with query: coap:<type>:/manual/endpoint/path?query")
        print(f"Allowed types: {allowed_types}")
    else:
        ep_type = tokens[1]
        ep_uri_with_query = tokens[2].split("?")

        ep_uri = ep_uri_with_query[0]
        ep_query = ""
        if len(ep_uri_with_query) == 2:
            ep_query = ep_uri_with_query[1]

        print(f"GET {ep_uri_with_query} (format: {ep_type})")
        with progress_bar() as progress:
            if ep_type == "file":
                outfile_path = ep_uri.replace("/", "_") + ".bin"
                print(f"Get file from {ep_uri} to {outfile_path}")
                return await coap.get_file(coap_ip_addr, ep_uri, outfile_path, progress)
            elif ep_type == "blockwise":
                outfile_path = ep_uri.replace("/", "_") + ".bin"
                print(f"Get file from {ep_uri} to {outfile_path}")
                return await coap.get_validated_blockwise(coap_ip_addr, ep_uri, outfile_path, progress)
            else:
                converter = get_data_formatter(ep_type)
                raw_result = await coap.get(coap_ip_addr, ep_uri, query=ep_query, leave_bytes=True)
                converted_result = converter(raw_result)
                return converted_result


async def device_exec_set_generic(coap_ip_addr: str, target: str, value: str):
    tokens = target.split(":")
    allowed_types = [*get_data_formatter_types(), "file", "blockwise"]

    if len(tokens) != 3 or tokens[0] != "coap" or tokens[1] not in allowed_types:
        print("Generic SET (POST) syntax: coap:<type>:/manual/endpoint/path")
        print("Generic SET (POST) syntax with query: coap:<type>:/manual/endpoint/path?query")
        return False
    else:
        input_type = tokens[1]
        ep_uri_with_query = tokens[2].split("?")

        ep_uri = ep_uri_with_query[0]
        ep_query = ""
        if len(ep_uri_with_query) == 2:
            ep_query = ep_uri_with_query[1]

        print(f"SET (POST) {ep_uri_with_query} (input format: {input_type}) -> {value}")
        if input_type == "file":
            filepath = value
            print(f"Post file from {filepath} to {ep_uri}")
            return await device_post_file(coap_ip_addr, ep_uri, filepath, target_filename=ep_query)
        elif input_type == "blockwise":
            filepath = value
            print(f"Post validated blockwise from {filepath} to {ep_uri}")
            with progress_bar() as progress:
                return await coap.post_validated_blockwise(coap_ip_addr, ep_uri, filepath, progress=progress)
        elif input_type == "json_str":
            formatter = get_data_formatter(input_type)
            return await coap.post_cbor(coap_ip_addr, ep_uri, formatter(value), query=ep_query)
        else:
            formatter = get_data_formatter(input_type)
            return await coap.post_text(coap_ip_addr, ep_uri, formatter(value), query=ep_query)


async def device_exec_get(coap_ip_addr: str, target: str):
    if target == "CONFIG":
        crc = await device_get_file_crc(coap_ip_addr, Endpoints.SINGLE_CONFIG)
        await device_get_file(coap_ip_addr, Endpoints.SINGLE_CONFIG, f"singleConfig_{crc}.cbor")
    elif target == "BLE_FW":
        crc = await device_get_file_crc(coap_ip_addr, Endpoints.BLE_FW)
        await device_get_file(coap_ip_addr, Endpoints.BLE_FW, f"blefw_{crc}.bin")
    elif target == "ISM_FW":
        crc = await device_get_file_crc(coap_ip_addr, Endpoints.ISM_FW)
        await device_get_file(coap_ip_addr, Endpoints.ISM_FW, f"ismfw_{crc}.bin")
    elif target == "DEV_FW":
        crc = await device_get_file_crc(coap_ip_addr, Endpoints.DEV_FW)
        await device_get_file(coap_ip_addr, Endpoints.DEV_FW, f"appimg_{crc}.bin")
    else:
        print(await device_exec_get_generic(coap_ip_addr, target))


async def device_exec_set(coap_ip_addr: str, target: str, value: str):
    print(f"Execute SET command {target} -> {value}")
    result = None
    if target == "BLE_FW":
        print("Write BLE_FW")
        result = await device_post_file(coap_ip_addr, "fs", value, target_filename="btRadioFw.freqHop.bin")
    elif target == "ISM_FW":
        print("Write ISM_FW")
        result = await device_post_file(coap_ip_addr, "fs", value, target_filename="ismfw.bin")
    elif target == "DEV_FW":
        print("Write device FW")
        result = await device_post_file(coap_ip_addr, "fs", value, target_filename="updateAppImg.bin")
    else:
        result = await device_exec_set_generic(coap_ip_addr, target, value)
    print(result)


async def device_exec_single_config(coap_ip_addr: str, json_path: str):
    single_config = {}
    with open(json_path) as rawfile:
        single_config = json.load(rawfile)
    await device_post_single_config(coap_ip_addr, single_config)


async def device_exec_secure_config(coap_ip_addr: str, filepath: str):
    print("Sending Configuration to Device")
    if TARGET_DEVICE == TargetDevice.EPC:
        with open(filepath, "rb") as cborfile:
            secure_config = cbor2.load(cborfile)
            return await coap.post_cbor(coap_ip_addr, Endpoints.SINGLE_CONFIG, secure_config)
    if TARGET_DEVICE == TargetDevice.NXP:
        return await device_post_file(coap_ip_addr, "fs", filepath, target_filename="secureConfig.cbor")


async def device_exec_web(coap_ip_addr: str, web_path=default_web_path):
    print(f"Connect to FORT Manager at {web_path}")
    try:
        auth_token = login(web_path, *get_user_credentials())
    except:
        print("ERROR: Unable to authenticate")
        return

    serial_number = input("Enter device serial number: ")
    try:
        single_config = get_device_config_from_fm(web_path, auth_token, serial_number)
    except FmResponseException as e:
        print(f"ERROR: {e}")
        return

    if single_config is None:
        print("ERROR: Unable to retrieve configuration file")
        return

    # POST Secure Config
    try:
        await device_exec_secure_config(coap_ip_addr, single_config)
    except coap.ClientException as e:
        print(f"ERROR: {e}")
        print("Failed to send configuration to device")
        return
    except:
        print("Failed to send configuration to device")
        return

    print("Successfully sent configuration to device")
    return


async def device_exec_reboot(coap_ip_addr: str, bootloader=False):
    await device_exec_set_generic(coap_ip_addr, f"coap:string:{Endpoints.SYSTEM_RESET}", 'b' if bootloader else 'n')
    print("Device rebooted.")


def run_menu(coap_ip_addr: str, cli_cfg, json_path=""):
    if json_path == "":
        if cli_cfg.nxp:
            raw_cfg = pkg_resources.resource_string("fort_cli_cfg", "data/frc.json")
        elif cli_cfg.epc:
            raw_cfg = pkg_resources.resource_string("fort_cli_cfg", "data/epc.json")
    else:
        with open(json_path, "rt") as fp:
            raw_cfg = fp.read()
    top_menu = build_endpoint(json.loads(raw_cfg))
    asyncio.get_event_loop().run_until_complete(top_menu.do_menu_loop(coap_ip_addr))


def cfgtool():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version=f'Version: {__version__}',
                        help="Show tool version number")

    cfg_args = parser.add_mutually_exclusive_group(required=True)
    cfg_args.add_argument('-J', '--json-single-config',
                          help='Upload single config from path specified (SRC Pro 4.1.0, EPC 1.1.0)')
    cfg_args.add_argument('-C', '--cbor-secure-config',
                          help='Upload secure config from path specified (SRC Pro 4.2.0, EPC 1.3.0)')
    cfg_args.add_argument('-w', '--web', action="store_true",
                          help='Uploading secure-config from FORT Manager')
    cfg_args.add_argument('-g', '--get', metavar=("TARGET"),
                          help='GET [INFO, CONFIG, BLE_FW, ISM_FW, DEV_FW, coap:<type>:/manual/path]')
    cfg_args.add_argument('-s', '--set', metavar=("TARGET", "VALUE"), nargs=2,
                          help='SET [BLE_FW, ISM_FW, DEV_FW, coap:<type>:/manual/endpoint/path]')
    cfg_args.add_argument('-r', '--reboot', action="store_true",
                          help="Reboot the device")
    cfg_args.add_argument('-m', '--menu', action="store_true",
                          help="Spawn an interactive menu for either the NXP or EPC")
    cfg_args.add_argument('-j', "--menu-json", help="Spawn a menu from a specified JSON")

    cfg_args = parser.add_mutually_exclusive_group(required=False)
    cfg_args.add_argument('-u', "--url", help="Provide URL for a specific web api")

    cfg_args = parser.add_mutually_exclusive_group(required=True)
    cfg_args.add_argument('-e', '--epc',
                          help='EPC output connection. Accepts an IP, such as 192.168.3.10')
    cfg_args.add_argument('-n', '--nxp',
                          help='NXP (SRC Pro / NSC) output connection. Accepts a serial interface, like /dev/ttyACM0')

    cli_cfg = parser.parse_args()

    coap_ip_addr: str
    bridge = None

    global Endpoints
    global TARGET_DEVICE

    if cli_cfg.epc:
        if cli_cfg.epc.startswith("/dev/"):
            bridge = SingleClientSerialUdpBridge(serial=Serial(port=cli_cfg.epc, baudrate=115200))
        coap_ip_addr = cli_cfg.epc

        Endpoints = EPCEndpoints
        TARGET_DEVICE = TargetDevice.EPC

    elif cli_cfg.nxp:
        print(f"Connect to NXP through {cli_cfg.nxp}")
        try:
            bridge = SingleClientSerialUdpBridge(serial=Serial(port=cli_cfg.nxp, baudrate=115200))
            bridge.start()
            coap_ip_addr = "{}:{}".format(*bridge.socket_addr)

            Endpoints = NXPEndpoints
            TARGET_DEVICE = TargetDevice.NXP
        except SerialException:
            print(f"ERROR: Device not found at {cli_cfg.nxp}")
            return
    else:
        raise RuntimeError("Please supply either `-n/--nxp </dev/ttyACM*>` OR `-e/--epc <IP>` ")

    # Determine the command to actually run from the output method
    if cli_cfg.json_single_config:
        asyncio.get_event_loop().run_until_complete(device_exec_single_config(coap_ip_addr, cli_cfg.json_single_config))
    elif cli_cfg.cbor_secure_config:
        asyncio.get_event_loop().run_until_complete(device_exec_secure_config(coap_ip_addr, cli_cfg.cbor_secure_config))
    elif cli_cfg.web:
        if cli_cfg.url:
            asyncio.get_event_loop().run_until_complete(device_exec_web(coap_ip_addr, cli_cfg.url))
        else:
            asyncio.get_event_loop().run_until_complete(device_exec_web(coap_ip_addr))
    elif cli_cfg.get:
        asyncio.get_event_loop().run_until_complete(device_exec_get(coap_ip_addr, cli_cfg.get))
    elif cli_cfg.set:
        asyncio.get_event_loop().run_until_complete(device_exec_set(coap_ip_addr, *cli_cfg.set))
    elif cli_cfg.reboot:
        asyncio.get_event_loop().run_until_complete(device_exec_reboot(coap_ip_addr))
    elif cli_cfg.menu:
        run_menu(coap_ip_addr, cli_cfg)
    elif cli_cfg.menu_json:
        run_menu(coap_ip_addr, cli_cfg, cli_cfg.menu_json)
    else:
        raise RuntimeError("Please supply one of [--json | --web | --set | --get | --reboot | --reboot-bootloader]")

    if bridge:
        bridge.stop()


if __name__ == "__main__":
    cfgtool()
