import asyncio
import json
import os
import readline
import glob
import pathlib
import re
import subprocess
import tempfile
import time
from contextlib import contextmanager
from typing import Any, Callable, List, Union

import invoke
from simple_term_menu import TerminalMenu

from . import coap
from .coap import FileInfo

from .validators import Validator_t, get_validator, get_data_formatter, IsmAddr, frc_validate_machine_index

import hashlib

paired_device_name_endpoint = "cfg/setup/pairedDeviceName"


def path_completer(text, state):
    """
    This is the tab completer for systems paths.
    Only tested on *nix systems
    """

    if '~' in text:
        text = os.path.expanduser('~')

    return [x for x in glob.glob(text + '*')][state]


readline.set_completer_delims('\t')
readline.parse_and_bind("tab: complete")
readline.set_completer(path_completer)


@contextmanager
def progress_bar(width=30, remaining_char=u'\u25A1', completed_char=u'\u25A0'):
    start = time.time()

    def update(numerator, denominator):
        progress = (numerator * width) // denominator
        elapsed = time.time() - start
        remaining = '?' if not numerator else int(elapsed * (1 - (numerator / denominator)) / (numerator / denominator))
        print(
            f"\r{completed_char * progress}{remaining_char * (width - progress)} " +  # noqa: W504
            f"{(numerator / denominator):>{' '}6.2%} " +  # noqa: W50
            f"({numerator:>{len(str(denominator))}}/{denominator}) elapsed {int(elapsed)}s. remaining {remaining}s... ",
            end='', flush=True
        )

    print(flush=True)

    yield update

    print(flush=True)


async def swap_loop(device: str, name: str, path: str, validation_fn: Validator_t, description: str, **kwargs):
    content_format = kwargs.get('content_format', None)
    formatter = kwargs.get('data_formatter', str)

    cur_val = await coap.get(
        device, path, content_format=content_format, leave_bytes=kwargs.get('ignore_content_format', False)
    )

    if description:
        print(f"{description}")
    print(f"Current {name}: {formatter(cur_val)}")
    await asyncio.sleep(.1)

    while True:
        new_val = input(f"Enter new {name} (blank for unchanged): ")
        if new_val != "":
            try:
                new_val = validation_fn(new_val)
                break
            except ValueError as value_error:
                print(f"Value Error: {value_error}")
            except:
                print("Invalid value provided")
                await asyncio.sleep(.1)
        else:
            return None

    if content_format is None or content_format in (coap.ContentFormat.JSON, coap.ContentFormat.CBOR):
        ppath = pathlib.PosixPath(path)
        endpoint = ppath.parent
        data_key = ppath.name
        post_fn = coap.post_json

        if content_format == coap.ContentFormat.CBOR:
            endpoint = ppath
            # need to convert from camelCase to snake_case for CBOR keys
            data_key = re.sub(
                r'^(.+)([A-Z])(.+)$',
                lambda pattern: f'{pattern.group(1)}_{pattern.group(2).lower()}{pattern.group(3)}',
                ppath.name
            )
            post_fn = coap.post_cbor

        ret = await post_fn(device, f'{endpoint}', {f'{data_key}': new_val})
    # new_val is a string so it's either going to be one of the two structured formats handled above or it's going to be
    # basically plain text (but we set the content type)
    else:
        ret = await coap.post_text(device, path, new_val, content_format=content_format)

    print(f"Device returned: {ret.code} - {ret.payload}")
    await asyncio.sleep(.1)
    return True


class Endpoint(object):
    def __init__(self, name: str):
        self.name = name

    async def selection_action(self, device: str, **kwargs):
        pass


class SingleRwEndpoint(Endpoint):
    def __init__(self, name: str, endpoint: str, validator: Validator_t, description=""):
        super().__init__(name)
        self.endpoint = endpoint
        self.validator = validator
        self.description = description

    async def selection_action(self, device: str, **kwargs):
        await swap_loop(device, self.name, self.endpoint, self.validator, self.description, **kwargs)


class SingleRwEndpointWithType(SingleRwEndpoint):
    def __init__(
        self, name: str, endpoint: str,
        validator: Validator_t, content_format: coap.ContentFormat, data_formatter: Callable[[Any], str] = str,
        description=""
    ):
        super().__init__(name, endpoint, validator, description)
        self.content_format = content_format
        self.data_formatter = data_formatter

    async def selection_action(self, device: str, **kwargs):
        return await super().selection_action(
            device, content_format=self.content_format, data_formatter=self.data_formatter, **kwargs
        )


class SingleRwEndpointWithFakeCBORType(SingleRwEndpointWithType):
    def __init__(self, name: str, endpoint: str, validator: Validator_t, description=""):
        super().__init__(
            name, endpoint, validator,
            content_format=coap.ContentFormat.CBOR, data_formatter=lambda x: str(int.from_bytes(x, 'little')),
            description=description
        )

    async def selection_action(self, device: str, **kwargs):
        return await super().selection_action(device, ignore_content_format=True, **kwargs)


class BlePeerMacAddressRwEndpoint(SingleRwEndpointWithType):
    def __init__(
        self, name: str, endpoint: str,
        validator: Validator_t, content_format: coap.ContentFormat,
        data_formatter: Callable[[Any], str] = str, description=""
    ):
        super().__init__(name, endpoint, validator, content_format, data_formatter, description)

    async def selection_action(self, device: str, **kwargs):
        index_id = input(f"Enter new {self.name} index_id (0-9): ")
        index_id = frc_validate_machine_index(index_id)
        max_character_count = 30
        current_mac_address = await coap.get(
            device, self.endpoint, query=f'{index_id}',
            content_format=coap.ContentFormat.TextPlain
        )
        await asyncio.sleep(.1)
        current_paired_device_name = await coap.get(
            device, paired_device_name_endpoint, query=f'{index_id}]',
            content_format=coap.ContentFormat.TextPlain
        )
        print(f"Current {self.name}: {current_mac_address}")
        print(f"Current paired device name: {current_paired_device_name}")
        while True:
            mac_address = input(f"Enter new {self.name} mac address (blank for unchanged): ")
            device_name = input(f"Enter new {self.name} device name (blank for unchanged): ")
            device_name = device_name if device_name else current_paired_device_name

            # If a mac address or name is not provided use the currently stored value
            if mac_address == "":
                mac_address = current_mac_address
            if device_name == "":
                device_name = current_paired_device_name

            if len(device_name) > max_character_count:
                device_name = device_name[:max_character_count]

            if mac_address == current_mac_address and device_name == current_paired_device_name:
                return None
            try:
                mac_address = self.validator(mac_address)
                break
            except ValueError as e:
                print(f"Error: Invalid mac address - {e}")

        try:
            ret = await coap.post(
                device, self.endpoint, query=f'{index_id}',
                payload=mac_address.encode(), content_format=coap.ContentFormat.TextPlain
            )
            print(f"Device returned {ret.code} - {ret.payload}")
            await asyncio.sleep(.1)

            ret = await coap.post(
                device, paired_device_name_endpoint, query=f'{index_id}',
                payload=device_name.encode(), content_format=coap.ContentFormat.TextPlain
            )
            print(f"Device returned {ret.code} - {ret.payload}")
        except coap.ClientException as e:
            print(f"Error: could not post new value - {e}")

        await asyncio.sleep(.1)
        return True


class BleRemovePeerRwEndpoint(SingleRwEndpointWithType):
    def __init__(
        self, name: str, endpoint: str,
        validator: Validator_t, content_format: coap.ContentFormat,
        data_formatter: Callable[[Any], str] = str, description=""
    ):
        super().__init__(name, endpoint, validator, content_format, data_formatter, description)

    async def selection_action(self, device: str, **kwargs):
        print("Ble Remove Peer Rw Endpoint")
        index_id = input("Enter index_id (0-9) to remove the paired list (blank to exit):")
        if index_id == "":
            return None
        index_id = frc_validate_machine_index(index_id)
        current_address = await coap.get(
            device, self.endpoint, query=f'{index_id}',
            content_format=coap.ContentFormat.TextPlain
        )
        await asyncio.sleep(.1)
        current_paired_device_name = await coap.get(
            device, paired_device_name_endpoint, query=f'{index_id}',
            content_format=coap.ContentFormat.TextPlain
        )
        print(f"Removing paired device: {current_paired_device_name} ({current_address})")
        try:
            zero_address = "00:00:00:00:00:00"
            ret = await coap.post_text(
                device, self.endpoint, query=f'{index_id}',
                payload=zero_address.encode(), content_format=self.content_format
            )
            print(f"Device returned {ret.code} - {ret.payload}")

            ret = await coap.post_text(
                device, paired_device_name_endpoint, query=f'{index_id}',
                payload="".encode(), content_format=coap.ContentFormat.TextPlain
            )
            print(f"Device returned {ret.code} - {ret.payload}")
        except coap.ClientException as e:
            print(f"Error could not post new value - {e}")
            return False

        await asyncio.sleep(.1)
        return True


class IsmAddressRwEndpoint(SingleRwEndpointWithType):
    def __init__(
            self, name: str, endpoint: str,
            validator: Validator_t, content_format: coap.ContentFormat, data_formatter: Callable[[Any], str] = str,
            description=""
    ):
        super().__init__(name, endpoint, validator, content_format, data_formatter, description)

    async def selection_action(self, device: str, **kwargs):
        data = await coap.get(device, self.endpoint, content_format=self.content_format, leave_bytes=True)
        print(f"Data: {data}")
        current_address = IsmAddr.parse(data)
        print(f"Current {self.name}: {current_address}")
        while True:
            print("ISM Address RW Endpoint")
            network_id = input(f'Enter new {self.name} network_id (0 - 65535) (blank for unchanged): ')
            network_id = int(network_id) if network_id else current_address.network_id
            device_id = input(f'Enter new {self.name} device_id (0 - 65535) (blank for unchanged): ')
            device_id = int(device_id) if device_id else current_address.device_id

            new_address = IsmAddr(network_id, device_id, 0)
            if new_address == current_address:
                return None
            try:
                new_address.validate()
                break
            except ValueError as e:
                print(f'Error: Invalid ISM address - {e}')

        try:
            ret = await coap.post_text(device, self.endpoint, new_address.format(), content_format=self.content_format)
        except coap.ClientException as e:
            print(f'Error: Could not POST new value - {e}')
            return False

        print(f'Device returned {ret.code} - {ret.payload}')
        await asyncio.sleep(.1)
        return True


class IsmAddressPeerRwEndpoint(SingleRwEndpointWithType):
    def __init__(
        self, name: str, endpoint: str,
        validator: Validator_t, content_format: coap.ContentFormat, data_formatter: Callable[[Any], str] = str,
        description=""
    ):
        super().__init__(name, endpoint, validator, content_format, data_formatter, description)

    async def selection_action(self, device: str, **kwargs):
        print("ISM Address Peer RW Endpoint")
        index_id = input(f"Enter new {self.name} index_id (0-9): ")
        index_id = frc_validate_machine_index(index_id)
        max_character_count = 30
        data = await coap.get(
            device, self.endpoint, query=f'{index_id}',
            content_format=self.content_format, leave_bytes=True
        )
        await asyncio.sleep(.1)
        current_address = IsmAddr.parse(data)
        current_paired_device_name = await coap.get(
            device, paired_device_name_endpoint, query=f'{index_id}',
            content_format=coap.ContentFormat.TextPlain
        )
        print(f"Current {self.name}: {current_address}")
        print(f"Current paired device name: {current_paired_device_name}")
        while True:
            network_id = input(f"Enter new {self.name} network_id (0 - 65535) (blank for unchanged): ")
            network_id = int(network_id) if network_id else current_address.network_id
            device_id = input(f"Enter new {self.name} device_id (0 - 65535) (blank for unchanged): ")
            device_id = int(device_id) if device_id else current_address.device_id
            device_name = input(f"Enter new {self.name} device_name (blank for unchanged): ")
            device_name = device_name if device_name else current_paired_device_name
            if len(device_name) > max_character_count:
                device_name = device_name[:max_character_count]

            new_address = IsmAddr(network_id, device_id, 0)
            if new_address == current_address and device_name == current_paired_device_name:
                return None
            try:
                new_address.validate()
                break
            except ValueError as e:
                print(f"Error: Invalid ISM address - {e}")

        try:
            ret = await coap.post_text(
                device, self.endpoint, new_address.format(),
                query=f'{index_id}', content_format=self.content_format
            )
            print(f"Device returned {ret.code} - {ret.payload}")
            await asyncio.sleep(.1)

            ret = await coap.post(
                device, paired_device_name_endpoint, query=f'{index_id}',
                payload=device_name.encode(), content_format=coap.ContentFormat.TextPlain
            )
            print(f"Device returned {ret.code} - {ret.payload}")

        except coap.ClientException as e:
            print(f"Error could not Post new value - {e}")
            return False

        await asyncio.sleep(.1)
        return True


class IsmRemovePeerRwEndpoint(SingleRwEndpointWithType):
    def __init__(
        self, name: str, endpoint: str,
        validator: Validator_t, content_format: coap.ContentFormat,
        data_formatter: Callable[[Any], str] = str, description=""
    ):
        super().__init__(name, endpoint, validator, content_format, data_formatter, description)

    async def selection_action(self, device: str, **kwargs):
        print("ISM Remove Peer Rw Endpoint")
        index_id = input("Enter index_id (0-9) to remove from the paired list (blank to exit): ")
        if index_id == "":
            return None
        index_id = frc_validate_machine_index(index_id)
        address_data = await coap.get(
            device, self.endpoint, query=f'{index_id}',
            content_format=self.content_format, leave_bytes=True
        )
        await asyncio.sleep(.1)
        current_address = IsmAddr.parse(address_data)
        current_paired_device_name = await coap.get(
            device, paired_device_name_endpoint, query=f'{index_id}',
            content_format=coap.ContentFormat.TextPlain
        )
        print(f"Removing paired device: {current_paired_device_name} ({current_address})")
        try:
            zero_address = IsmAddr(0, 0, 0)
            ret = await coap.post_text(
                device, self.endpoint, zero_address.format(),
                query=f'{index_id}', content_format=self.content_format
            )
            print(f"Device returned {ret.code} - {ret.payload}")
            await asyncio.sleep(.1)

            ret = await coap.post(
                device, paired_device_name_endpoint, query=f'{index_id}',
                payload="".encode(), content_format=coap.ContentFormat.TextPlain
            )
            print(f"Device returned {ret.code} - {ret.payload}")

        except coap.ClientException as e:
            print(f"Error could not post new value - {e}")
            return False

        await asyncio.sleep(.1)
        return True


class SafetyCareDeviceEndpoint(SingleRwEndpoint):
    def __init__(
        self, name: str,
        endpoint: str,
        validator: Validator_t,
        data_formatter: Callable[[Any], str] = str,
        description=""
    ):
        super().__init__(name, endpoint, validator, description)

    async def selection_action(self, device: str, **kwargs):
        print(f"Menu name: {self.name}")
        care_index = input("Enter Care device index (0-4): ")
        if care_index == '':
            return
        elif 0 <= int(care_index) <= 4:
            print(f"Care{care_index} device selected")
        else:
            print("Invalid Care device index. Must be a value between 0 - 4.")
            return

        # Replace care# with the user provided care index in the endpoint
        endpoint_search = "care0"
        search_result = re.search(endpoint_search, self.endpoint)
        if search_result is None:
            print(f"Invalid Care endpoint: {self.endpoint}")
            return
        new_care_device = "care" + care_index
        new_endpoint = self.endpoint.replace(endpoint_search, new_care_device)

        current_value = await coap.get(device, new_endpoint)
        await asyncio.sleep(.1)
        print(f"Current {self.name}: {current_value}")

        if self.description:
            print(f"{self.description}")

        if self.name == "Delete Care Device":
            new_value = 0xFFFF
        else:
            new_value = input(f"Enter new {self.name} (blank for unchanged): ")
            if new_value == '':
                return
            try:
                new_value = self.validator(new_value)
            except Exception as e:
                print(f"{new_value} is an invalid value {e}")
                return None

        if type(new_value) == int:
            ret = await coap.post_text(device,
                                       new_endpoint,
                                       str(new_value),
                                       content_format=coap.ContentFormat.TextPlain)
        else:
            ppath = pathlib.PosixPath(new_endpoint)
            endpoint = ppath.parent
            data_key = ppath.name
            ret = await coap.post_json(device, f'{endpoint}', {f'{data_key}': new_value})

        print(f"Device returned: {ret.code} - {ret.payload}")
        await asyncio.sleep(.1)


class ISMVersionRoEndpoint(Endpoint):
    def __init__(self, name: str, endpoint: str):
        self.name = name
        self.endpoint = endpoint

    async def selection_action(self, device: str, **kwargs):
        obsv = await coap.get(device, self.endpoint)
        print(obsv)
        await asyncio.sleep(.1)


class SingleRoEndpoint(Endpoint):
    def __init__(self, name: str, endpoint: str):
        self.name = name
        self.endpoint = endpoint

    async def selection_action(self, device: str, **kwargs):
        obsv = await coap.get(device, self.endpoint)
        print(json.dumps(obsv, indent=4, sort_keys=True))
        await asyncio.sleep(.1)


class SingleRoEndpointWithType(SingleRoEndpoint):
    def __init__(
            self, name: str, endpoint: str,
            content_format: coap.ContentFormat, data_formatter: Callable[[Any], str] = str
    ):
        super().__init__(name, endpoint)
        self.content_format = content_format
        self.data_formatter = data_formatter

    async def selection_action(self, device: str, **kwargs):
        current_value = await coap.get(device, self.endpoint, content_format=self.content_format, **kwargs)
        if current_value is not None:
            print(f'{self.name}: {self.data_formatter(current_value)}\n')

        await asyncio.sleep(.1)


class SingleRoEndpointWithFakeCBORType(SingleRoEndpointWithType):
    """
    This endpoint type is meant for fl/*/length and fl/*/crc endpoints on the FRC whose content types are CBOR but whose
    responses are not (always) valid CBOR
    """

    def __init__(self, name: str, endpoint: str):
        super().__init__(name, endpoint, coap.ContentFormat.CBOR, lambda x: hex(int.from_bytes(x, 'little')))

    async def selection_action(self, device: str, **kwargs):
        return await super().selection_action(device, leave_bytes=True)


class FileMetadataEndpoint(Endpoint):
    def __init__(self, name: str, endpoint: str, metadata_endpoint: str, target_filename: str):
        self.name = name
        self.endpoint = endpoint
        self.metadata_endpoint = metadata_endpoint
        self.target_filename = target_filename

    async def selection_action(self, device: str, **kwargs):
        if not await coap.post_text(device, self.endpoint, self.target_filename):
            print(f"Could not prepare target to download metadata for {self.target_filename}")
            return False

        raw_result = bytes(await coap.get(device, self.metadata_endpoint, query="computed", leave_bytes=True))
        print(FileInfo.from_bytes(raw_result))


class FolderMetadataEndpoint(Endpoint):
    def __init__(self, name: str, endpoint: str, metadata_endpoint: str, target_filenames: list):
        self.name = name
        self.endpoint = endpoint
        self.metadata_endpoint = metadata_endpoint
        self.target_filenames = target_filenames

    async def selection_action(self, device: str, **kwargs):
        for target_filename in self.target_filenames:
            if not await coap.post_text(device, self.endpoint, target_filename):
                print(f"Could not prepare target to download metadata for {target_filename}")
                return False

            raw_result = bytes(await coap.get(device, self.metadata_endpoint, query="computed", leave_bytes=True))
            print("{}: {}".format(target_filename, FileInfo.from_bytes(raw_result)))
        return True


class ValidatedBlockwiseEndpoint(Endpoint):
    def __init__(self, name: str, endpoint: str, path: str):
        super().__init__(name)
        self.endpoint = endpoint
        self.path = pathlib.Path(path)


class ValidatedBlockwiseReadEndpoint(ValidatedBlockwiseEndpoint):
    def __init__(self, name: str, endpoint: str, path: str):
        super().__init__(name, endpoint, path)

    async def selection_action(self, device: str, **kwargs):
        path = input(f'Enter output file path or leave blank to accept default ({self.path}): ')
        if path:
            self.path = pathlib.Path(path)
        with progress_bar() as progress:
            await coap.get_validated_blockwise(device, self.endpoint, self.path, progress=progress)
        await asyncio.sleep(.1)


class ValidatedBlockwiseWriteEndpoint(ValidatedBlockwiseEndpoint):
    def __init__(self, name: str, endpoint: str, path: str):
        super().__init__(name, endpoint, path)

    async def selection_action(self, device: str, **kwargs):
        path = input(f'Enter input file path or leave blank to accept default ({self.path}): ')
        if path:
            self.path = pathlib.Path(path)

        with progress_bar() as progress:
            await coap.post_validated_blockwise(device, self.endpoint, self.path, progress=progress)

        await asyncio.sleep(.1)


class FileEndpoint(Endpoint):
    def __init__(self, name: str, target_filename: str, endpoint: str, path: str, file_info_endpoint: str):
        super().__init__(name)
        self.target_filename = target_filename
        self.endpoint = endpoint
        self.path = pathlib.Path(path)
        self.file_info_endpoint = file_info_endpoint


class FileReadEndpoint(FileEndpoint):
    def __init__(self, name: str, target_filename: str, endpoint: str, path: str, file_info_endpoint: str):
        super().__init__(name, target_filename, endpoint, path, file_info_endpoint)

    async def selection_action(self, device: str, **kwargs):
        path = input(f'Enter output file path or leave blank to accept default ({self.path}): ')
        if path:
            self.path = pathlib.Path(path)

        if not await coap.post_text(device, self.endpoint, self.target_filename):
            print(f"Could not prepare target to send file {self.target_filename}")
            return False

        with progress_bar() as progress:
            await coap.get_file(
                device, self.endpoint, self.file_info_endpoint, self.path, self.target_filename, progress=progress)

        await asyncio.sleep(.1)


class FileWriteEndpoint(FileEndpoint):
    def __init__(self, name: str, target_filename: str, endpoint: str, path: str, file_info_endpoint: str):
        super().__init__(name, target_filename, endpoint, path, file_info_endpoint)

    async def selection_action(self, device: str, **kwargs):
        path = input(f'Enter input file path or leave blank to accept default ({self.path}): ')
        if path:
            self.path = pathlib.Path(path)

        with progress_bar() as progress:
            await coap.post_file(
                device, self.endpoint, self.file_info_endpoint, self.path, self.target_filename, progress=progress)

        await asyncio.sleep(.1)


class FolderEndpoint(Endpoint):
    def __init__(self, name: str, target_filenames: list, endpoint: str, file_info_endpoint: str):
        super().__init__(name)
        self.target_filenames = target_filenames
        self.endpoint = endpoint
        self.file_info_endpoint = file_info_endpoint


class FolderReadEndpoint(FolderEndpoint):
    def __init__(self, name: str, target_filenames: str, endpoint: str, file_info_endpoint: str):
        super().__init__(name, target_filenames, endpoint, file_info_endpoint)

    async def selection_action(self, device: str, **kwargs):
        output_path = input("Enter output folder path: ")
        if not output_path:
            return False

        os.makedirs(output_path, exist_ok=True)

        for target_filename in self.target_filenames:
            output_filename = os.path.join(output_path, target_filename)

            print("Download file '{}' to '{}'".format(target_filename, output_filename))
            with progress_bar() as progress:
                await coap.get_file(
                    device, self.endpoint, self.file_info_endpoint, output_filename, target_filename, progress=progress)

            await asyncio.sleep(.1)


class FolderWriteEndpoint(FolderEndpoint):
    def __init__(self, name: str, target_filenames: list, endpoint: str, local_paths: list, file_info_endpoint: str):
        super().__init__(name, target_filenames, endpoint, file_info_endpoint)

    async def selection_action(self, device: str, **kwargs):
        input_path = input("Enter input folder path which contains {}: ".format(self.target_filenames))
        if not input_path:
            return False

        for target_filename in self.target_filenames:
            input_filename = os.path.join(input_path, target_filename)

            print("Upload file {}".format(input_filename))
            with progress_bar() as progress:
                await coap.post_file(
                    device, self.endpoint, self.file_info_endpoint, input_filename, target_filename, progress=progress)

            await asyncio.sleep(.1)


class SingleWoEndpoint(Endpoint):
    def __init__(self, name: str, endpoint: str, value: str):
        super().__init__(name)
        self.name = name
        self.endpoint = endpoint
        self.value = value

    async def selection_action(self, device: str, **kwargs):
        ret = await coap.post_text(device, self.endpoint, self.value, **kwargs)
        print(f"Device returned: {ret.code} - {ret.payload}\n")
        await asyncio.sleep(.1)


class SingleRebootEndpoint(Endpoint):
    def __init__(self, name: str, prompt: str, action_descriptor: dict, validator: Validator_t):
        self.name = name
        self.prompt = prompt
        self.actions = action_descriptor
        self.validator = validator

    async def selection_action(self, device: str):
        val = input(self.prompt)
        try:
            val = self.validator(val)
            act = self.actions[val]
            for ep, payload in act:
                ret = await coap.post(device, ep, payload=payload)
                if ret.code.is_successful():
                    print("EPC reboot command successful")
                    print("  {}".format(ret.payload.decode("utf-8")))
                else:
                    print("EPC reboot command failed")
            await asyncio.sleep(.1)
        except ValueError:
            return


class SingleWoEndpointWithType(SingleWoEndpoint):
    def __init__(self, name: str, endpoint: str, value: str, content_format: coap.ContentFormat):
        super().__init__(name, endpoint, value)
        self.content_format = content_format

    async def selection_action(self, device: str, **kwargs):
        return await super().selection_action(device, content_format=self.content_format, **kwargs)


class WriteFileSha(Endpoint):
    """
    Upload file mapped in (length, data, sha256) as CBOR message
    """
    def __init__(self, name: str, endpoint: str, path: str, validator: Validator_t, maxSize: int):
        self.name = name
        self.endpoint = endpoint
        self.validator = validator
        self.path = path
        self.maxSize = maxSize

    async def selection_action(self, device: str):
        path = input(f'Enter input file path or leave blank to accept default ({self.path}): ')
        if not path:
            path = self.path
        if self.validator(path, self.maxSize):
            with open(path, "rb") as f:
                data = f.read()
            shaStr = hashlib.sha256(data).hexdigest()
            payload = {"length": len(data), "data": data, "sha256": shaStr}
            ret = await coap.post_cbor(device, self.endpoint, payload=payload)
            try:
                if ret.code.is_successful():
                    print("  {}".format(ret.payload.decode("utf-8")))
                else:
                    print("EPC Firmware update fialed")
                    await asyncio.sleep(.1)
            except:
                return


class DiscreteCfgMultiPostEndpoint(Endpoint):
    def __init__(
            self, name: str, prompt: str, action_descriptor: dict, validator: Validator_t
    ):
        self.name = name
        self.prompt = prompt
        self.actions = action_descriptor
        self.validator = validator

    # expected structure of the 'action_descriptor' argument
    # { "i": [ (ep, payload), (ep, payload) ],
    #   "o": [ (ep, payload),

    async def selection_action(self, device: str, **kwargs):
        val = input(self.prompt)
        val = self.validator(val)

        act = self.actions[val]
        for ep, payload in act:
            ret = await coap.post_json(device, ep, payload)
            print(ret.payload)
        await asyncio.sleep(.1)


class DiscreteCfgMultiGetEndpoint(Endpoint):
    def __init__(self, name: str, endpoints: str, labels: dict):
        self.name = name
        self.endpoints = endpoints
        self.labels = labels

    async def selection_action(self, device: str, **kwargs):
        match = None
        recved_vals = []

        for ep in self.endpoints:
            obsv = await coap.get(device, ep)
            recved_vals += [obsv]
            await asyncio.sleep(.1)

        for key in self.labels.keys():
            if recved_vals == self.labels[key]:
                match = key

        if match is None:
            print("Current config does not have a name")
        else:
            print("Current config is : {}".format(match))


class ObservableRwEndpoint(Endpoint):
    def __init__(self, name: str, endpoint: str, observables: dict, description=""):
        self.name = name
        self.endpoint = endpoint
        self.observables = observables
        self.description = description

    async def selection_action(self, device: str, **kwargs):
        cur_val = await coap.get(device, self.endpoint)

        if self.description:
            print(self.description)
        print("Current {name}: {cur_val}".format(name=self.name, cur_val=cur_val))
        await asyncio.sleep(.1)
        obsv_cfg = []
        while True:
            new_val = input(
                f"Enter new {self.name} ({list(map(str, self.observables.keys()))} or blank for unchanged): "
            )

            if new_val != "":
                try:
                    obsv_cfg = self.observables[new_val]
                    # Encode the JSON as an escaped string,
                    # while dropping the outermost '"' marks
                    obsv_cfg = json.dumps(obsv_cfg)
                    break
                except:
                    print("Invalid value provided")
                    await asyncio.sleep(.1)
            else:
                return None

        ppath = pathlib.PosixPath(self.endpoint)
        ret = await coap.post_json(device, f'{ppath.parent}', {ppath.name: obsv_cfg})
        print("Device returned: {} - {}".format(ret.code, ret.payload))
        await asyncio.sleep(.1)
        return True


class ObservableRoEndpoint(Endpoint):
    """
    This class is used to observe the response of endpoint
    """
    def __init__(self, name: str, endpoint: str):
        self.name = name
        self.endpoint = endpoint

    async def selection_action(self, device: str, **kwargs):
        try:
            await coap.get_response_observe(device, self.endpoint)
        except ConnectionRefusedError:
            print("Connection refused")
            return


class GetLogsEndpoint(Endpoint):
    def __init__(
            self, name: str,
            prompt: str,
            prompt_for_password: str,
            relavent_logs: list,
            validator: Validator_t
    ):
        self.name = name
        self.prompt = prompt
        self.prompt_for_password = prompt_for_password
        self.relavent_logs = relavent_logs
        self.validator = validator

    async def selection_action(self, device: str, **kwargs):
        sjr_location = ""
        sjr_found = False
        sjr_map = {
            "path": "systemd-journal-remote",
            "ubuntu_2004_loc": "/usr/lib/systemd/systemd-journal-remote",
            "ubuntu_1804_loc": "/lib/systemd/systemd-journal-remote"
        }

        ssh_location = ""
        ssh_found = False
        ssh_map = {
            "path": "ssh"
        }

        for key in sjr_map:
            exist = subprocess.call('command -v ' + sjr_map[key] + '>> /dev/null', shell=True)
            if exist == 0:
                print()
                sjr_location = sjr_map[key]
                sjr_found = True

        for key in ssh_map:
            exist = subprocess.call('command -v ' + ssh_map[key] + '>> /dev/null', shell=True)
            if exist == 0:
                ssh_location = ssh_map[key]
                ssh_found = True

        if ssh_found and sjr_found:
            tmp_dir = tempfile.gettempdir()
            journal_file = input(self.prompt)
            journal_file = self.validator(journal_file)
            log_list_with_tack_u = []
            for log_name in self.relavent_logs:
                log_list_with_tack_u.append("-u {}".format(log_name))
            pull_log_cmd = "{} root@{} journalctl {} -b -o export > {}/{}.jo".format(ssh_location, device,
                                                                                     " ".join(log_list_with_tack_u),
                                                                                     tmp_dir, journal_file)
            invoke.run(pull_log_cmd)
            unpack_log_cmd = "{} {}/{}.jo -o {}/{}.journal".format(sjr_location, tmp_dir, journal_file, tmp_dir,
                                                                   journal_file)
            invoke.run(unpack_log_cmd)
            print("Your file is waiting for you : {}/{}.journal".format(tmp_dir, journal_file))
            print("View it with : journalctl --file={}/{}.journal".format(tmp_dir, journal_file))
            # TODO, think about how to view inline with something like :
            # invoke.run("journalctl --file={}/{}.journal".format(tmp_dir, journal_file))
        else:
            print("This menu item needs both ssh and systemd-journal-remote")
            print('To install ssh:')
            print('sudo apt install ssh')
            print('To install systemd-journal-remote:')
            print('sudo apt install systemd-journal-remote')
            print('The easiest way to run this command is to put both on path')


class Menu(object):
    def __init__(self, name: str, endpoints: List[str], back_text: str = "Back"):
        self.endpoints = endpoints
        self.name = name

        menu_txt = [
            *("{}".format(e.name) for i, e in enumerate(self.endpoints))]
        menu_indx1 = [
            *("{}".format(i) for i in range(0, 10))]
        menu_indx2 = [
            *("{}".format(chr(i)) for i in range(97, 123))]
        menu_indx = menu_indx1 + menu_indx2

        menu_txt = [*("[{}] {}".format(i, n) for i, n in zip(menu_indx, menu_txt)), "[*] {}".format(back_text)]

        self.menu = TerminalMenu(menu_txt, title=self.name)

    async def do_menu_loop(self, device: str):
        while True:
            selection = self.menu.show()
            # selection == len(self.endpoints) for the 'quit/back' selection
            if selection < len(self.endpoints):
                entry = self.endpoints[selection]
                if isinstance(entry, Menu):
                    await entry.do_menu_loop(device)
                elif isinstance(entry, Endpoint):
                    try:
                        await entry.selection_action(device, )
                    except coap.ClientException as e:
                        print(f'COAP Error: {e}')
            else:
                break


def build_endpoint_list(descriptor: List[dict]) -> List[Endpoint]:
    return list(build_endpoint(ep_desc) for ep_desc in descriptor)


def get_description(descriptor: List[dict]) -> str:
    try:
        return descriptor['description']
    except KeyError:
        return ""


def build_endpoint(descriptor: dict) -> Union[Endpoint, Menu]:
    type_ = descriptor['type']
    if type_ == "Menu":
        args = {
            "name": descriptor['name'],
            "endpoints": build_endpoint_list(descriptor['menu'])
        }
        if descriptor.get("back"):
            args["back_text"] = descriptor["back"]
        return Menu(**args)
    elif type_ == "SingleRwEndpoint":
        return SingleRwEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            validator=get_validator(descriptor['args']['validator']),
            description=get_description(descriptor)
        )
    elif type_ == "SingleRwEndpointWithType":
        return SingleRwEndpointWithType(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            validator=get_validator(descriptor['args']['validator']),
            content_format=coap.ContentFormat[descriptor['args']['contentFormat']],
            data_formatter=get_data_formatter(descriptor['args'].get('dataFormat', '')),
            description=get_description(descriptor)
        )
    elif type_ == "SingleRwEndpointWithFakeCBORType":
        return SingleRwEndpointWithFakeCBORType(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            validator=get_validator(descriptor['args']['validator']),
            description=get_description(descriptor)
        )
    elif type_ == "BlePeerMacAddressRwEndpoint":
        return BlePeerMacAddressRwEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            validator=get_validator(descriptor['args']['validator']),
            content_format=coap.ContentFormat[descriptor['args']['contentFormat']],
            description=get_description(descriptor)
        )
    elif type_ == "BleRemovePeerRwEndpoint":
        return BleRemovePeerRwEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            validator=get_validator(descriptor['args']['validator']),
            content_format=coap.ContentFormat[descriptor['args']['contentFormat']],
            description=get_description(descriptor)
        )
    elif type_ == "IsmAddressRwEndpoint":
        return IsmAddressRwEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            validator=get_validator(descriptor['args']['validator']),
            content_format=coap.ContentFormat[descriptor['args']['contentFormat']],
            data_formatter=get_data_formatter(descriptor['args'].get('dataFormat', '')),
            description=get_description(descriptor)
        )
    elif type_ == "IsmAddressPeerRwEndpoint":
        return IsmAddressPeerRwEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            validator=get_validator(descriptor['args']['validator']),
            content_format=coap.ContentFormat[descriptor['args']['contentFormat']],
            data_formatter=get_data_formatter(descriptor['args'].get('dataFormat', '')),
            description=get_description(descriptor)
        )
    elif type_ == "IsmRemovePeerRwEndpoint":
        return IsmRemovePeerRwEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            validator=get_validator(descriptor['args']['validator']),
            content_format=coap.ContentFormat[descriptor['args']['contentFormat']],
            data_formatter=get_data_formatter(descriptor['args'].get('dataFormat', '')),
            description=get_description(descriptor)
        )
    elif type_ == "SafetyCareDeviceEndpoint":
        return SafetyCareDeviceEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            validator=get_validator(descriptor['args']['validator']),
            description=get_description(descriptor)
        )
    elif type_ == "ISMVersionRoEndpoint":
        return ISMVersionRoEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint']
        )
    elif type_ == "SingleRoEndpoint":
        return SingleRoEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint']
        )
    elif type_ == "SingleRoEndpointWithType":
        return SingleRoEndpointWithType(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            content_format=coap.ContentFormat[descriptor['args']['contentFormat']],
            data_formatter=get_data_formatter(descriptor['args'].get('dataFormat', ''))
        )
    elif type_ == "SingleRoEndpointWithFakeCBORType":
        return SingleRoEndpointWithFakeCBORType(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint']
        )
    elif type_ == "FolderMenu":
        args = {
            "name": descriptor['name'],
            "endpoints": build_endpoint_list([
                {
                    "name": "Folder Metadata",
                    "type": "FolderMetadataEndpoint",
                    "args": {
                        "name": "Compute on-device metadata for {}".format(str(descriptor["args"]["target_filenames"])),
                        "endpoint": descriptor["args"]["endpoint"],
                        "metadata_endpoint": descriptor["args"]["metadata_endpoint"],
                        "target_filenames": descriptor["args"]["target_filenames"],
                    },
                },
                {
                    "name": f"{descriptor['name']} folder data",
                    "type": "Menu",
                    "menu": [
                        {
                            "name": "Download files",
                            "type": "FolderReadEndpoint",
                            "args": descriptor["args"]
                        },
                        {
                            "name": "Upload files",
                            "type": "FolderWriteEndpoint",
                            "args": descriptor["args"]
                        }
                    ],
                }
            ])
        }
        return Menu(**args)
    elif type_ == "FolderMetadataEndpoint":
        return FolderMetadataEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            metadata_endpoint=descriptor['args']['metadata_endpoint'],
            target_filenames=descriptor["args"]["target_filenames"])
    elif type_ == "FolderReadEndpoint":
        return FolderReadEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            target_filenames=descriptor["args"]["target_filenames"],
            file_info_endpoint=descriptor["args"]["metadata_endpoint"]
        )
    elif type_ == "FolderWriteEndpoint":
        return FolderWriteEndpoint(
            name=descriptor['name'],
            target_filenames=descriptor["args"]["target_filenames"],
            endpoint=descriptor['args']['endpoint'],
            local_paths=descriptor["args"]["local_paths"],
            file_info_endpoint=descriptor["args"]["metadata_endpoint"]
        )
    elif type_ == "FileMenu":
        # a convenient pseudo-endpoint that generates a menu for a file endpoint
        # ( file menu -> (metadata -> (length + crc), data -> (read, write)) )
        args = {
            "name": descriptor['name'],
            "endpoints": build_endpoint_list([
                {
                    "name": "File Metadata",
                    "type": "FileMetadataEndpoint",
                    "args": {
                        "name": "Compute on-device metadata",
                        "endpoint": descriptor["args"]["endpoint"],
                        "metadata_endpoint": descriptor["args"]["metadata_endpoint"],
                        "target_filename": descriptor["args"]["target_filename"],
                    },
                },
                {
                    "name": f"{descriptor['name']} file data",
                    "type": "Menu",
                    "menu": [
                        {
                            "name": "Download file",
                            "type": "FileReadEndpoint",
                            "args": descriptor["args"]
                        },
                        {
                            "name": "Upload file",
                            "type": "FileWriteEndpoint",
                            "args": descriptor["args"]
                        }
                    ],
                }
            ])
        }
        return Menu(**args)
    elif type_ == "FileMenuRequestRo":
        # a convenient pseudo-endpoint that reads a file from the specified endpoint
        # ( file menu -> (request, length, crc, data -> (read)) )
        file_endpoint_args = {
            "endpoint": descriptor['args']['endpoint'],
            "path": descriptor['args']['path'],
        }
        args = {
            "name": descriptor['name'],
            "endpoints": build_endpoint_list([
                {
                    "name": f"Request {descriptor['args']['requestValue']}",
                    "type": "SingleWoEndpointWithType",
                    "args": {
                        "endpoint": f"{descriptor['args']['requestEndpoint']}",
                        "contentFormat": "TextPlain",
                        "value": f"{descriptor['args']['requestValue']}",
                    }
                },
                {
                    "name": "File length",
                    "type": "SingleRoEndpointWithFakeCBORType",
                    "args": {
                        "endpoint": f"{descriptor['args']['endpoint']}/length",
                    },
                },
                {
                    "name": "File CRC",
                    "type": "SingleRoEndpointWithFakeCBORType",
                    "args": {
                        "endpoint": f"{descriptor['args']['endpoint']}/crc",
                    },
                },
                {
                    "name": "Download File",
                    "type": "ValidatedBlockwiseReadEndpoint",
                    "args": file_endpoint_args
                },
            ])
        }
        return Menu(**args)
    elif type_ == "FileMenuRequestWo":
        # a convenient pseudo-endpoint that writes a file to the specified endpoint
        # ( file menu -> (request, length, crc, data -> (read)) )
        file_endpoint_args = {
            "endpoint": descriptor['args']['endpoint'],
            "path": descriptor['args']['path']
        }
        args = {
            "name": descriptor['name'],
            "endpoints": build_endpoint_list([
                {
                    "name": f"Request {descriptor['args']['requestValue']}",
                    "type": "SingleWoEndpointWithType",
                    "args": {
                        "endpoint": f"{descriptor['args']['requestEndpoint']}",
                        "contentFormat": "TextPlain",
                        "value": f"{descriptor['args']['requestValue']}",
                    }
                },
                {
                    "name": "Upload File",
                    "type": "ValidatedBlockwiseWriteEndpoint",
                    "args": {
                        **file_endpoint_args, 'fileInfo': descriptor['args'].get('fileInfo', None)
                    }
                },
            ])
        }
        return Menu(**args)
    elif type_ == "FileMetadataEndpoint":
        return FileMetadataEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            metadata_endpoint=descriptor['args']['metadata_endpoint'],
            target_filename=descriptor["args"]["target_filename"])
    elif type_ == "FileReadEndpoint":
        return FileReadEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            path=descriptor['args']['path'],
            target_filename=descriptor["args"]["target_filename"],
            file_info_endpoint=descriptor["args"]["metadata_endpoint"]
        )
    elif type_ == "FileWriteEndpoint":
        return FileWriteEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            path=descriptor['args']['path'],
            target_filename=descriptor["args"]["target_filename"],
            file_info_endpoint=descriptor["args"]["metadata_endpoint"]
        )
    elif type_ == "ValidatedBlockwiseReadEndpoint":
        return ValidatedBlockwiseReadEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            path=descriptor['args']['path']
        )
    elif type_ == "ValidatedBlockwiseWriteEndpoint":
        return ValidatedBlockwiseWriteEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            path=descriptor['args']['path']
        )
    elif type_ == "SingleWoEndpoint":
        return SingleWoEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            value=descriptor['args']['value']
        )
    elif type_ == "SingleWoEndpointWithType":
        return SingleWoEndpointWithType(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            content_format=coap.ContentFormat[descriptor['args']['contentFormat']],
            value=descriptor['args']['value']
        )
    elif type_ == "WriteFileSha":
        return WriteFileSha(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            path=descriptor['args']['path'],
            maxSize=descriptor['args']['maxSize'],
            validator=get_validator(descriptor['args']['validator'])
        )
    elif type_ == "SingleRebootEndpoint":
        return SingleRebootEndpoint(
            name=descriptor['name'],
            prompt=descriptor['args']['prompt'],
            action_descriptor=descriptor['args']['action_descriptor'],
            validator=get_validator(descriptor['args']['validator'])
        )
    elif type_ == "DiscreteCfgMultiPostEndpoint":
        return DiscreteCfgMultiPostEndpoint(
            name=descriptor['name'],
            prompt=descriptor['args']['prompt'],
            action_descriptor=descriptor['args']['action_descriptor'],
            validator=get_validator(descriptor['args']['validator'])
        )
    elif type_ == "DiscreteCfgMultiGetEndpoint":
        return DiscreteCfgMultiGetEndpoint(
            name=descriptor['name'],
            endpoints=descriptor['args']['endpoints'],
            labels=descriptor['args']['labels']
        )
    elif type_ == "ObservableRwEndpoint":
        return ObservableRwEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
            observables=descriptor['args']['observables'],
            description=get_description(descriptor)
        )
    elif type_ == "ObservableRoEndpoint":
        return ObservableRoEndpoint(
            name=descriptor['name'],
            endpoint=descriptor['args']['endpoint'],
        )
    elif type_ == "GetLogsEndpoint":
        return GetLogsEndpoint(
            name=descriptor['name'],
            prompt=descriptor['args']['prompt'],
            prompt_for_password=descriptor['args']['prompt_for_password'],
            relavent_logs=descriptor['args']['relavent_logs'],
            validator=get_validator(descriptor['args']['validator'])
        )
    else:
        raise Exception(f"Invalid endpoint type specified in configuration file: {descriptor['type']}")
