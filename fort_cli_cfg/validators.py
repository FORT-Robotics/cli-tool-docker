import re
import json
from enum import Enum
from functools import partial
from typing import NamedTuple
from typing import Union, Callable
import pathlib

Validator_t = Callable[[str], Union[str, bool, int]]


def validate_param(name: str, base_class, is_valid_func):
    class ValidatorClass(base_class):
        def __new__(cls, val):
            if is_valid_func(val):
                return base_class(val)
            raise ValueError(f"Invalid value({val}) for {name}")

    ValidatorClass.__name__ = name
    return ValidatorClass


def ranged_int_validator(min_val: int, max_val: int):
    return validate_param(f"int({min_val}-{max_val})", int, lambda v: min_val <= int(v) <= max_val)


uint8 = ranged_int_validator(0, 0xff)
uint16 = ranged_int_validator(0, 0xffff)


class IsmAddr(NamedTuple):
    network_id: uint16
    device_id: uint16
    input_id: uint16

    @staticmethod
    def parse(s: bytes) -> 'IsmAddr':
        """parse ism address from get-request body (comma-separated string of 3 ints)"""
        return IsmAddr(*(int(e) for e in s.decode().split(',')))

    def format(self) -> bytes:
        """format an ISM addr into a post-request body"""
        return f"{self.network_id},{self.device_id},{self.input_id}".encode()

    def validate(self):
        bad = []
        if not (0 <= self.network_id <= 65535):
            bad.append('network_id')
        if not (0 <= self.device_id <= 65535):
            bad.append('device_id')

        if any(bad):
            raise ValueError(f"{' and '.join(bad)} must be 0-65535")


class FrcMode(bytes, Enum):
    LOCAL = b'\x04'
    REMOTE = b'x06'
    OPERATIONAL = b'\x09'
    MENU = b'\x0A'
    PAUSE = b'\x0B'


class radioMode(bytes, Enum):
    CENTRAL = b'M'
    PERIPHERAL = b'S'
    TDMA_BASE = b'T'
    TDMA_REMOTE = b't'
    # ToDo: add the rest


def validate_peer_name(name: str) -> str:
    if len(name) > 8:
        raise Exception("Name must be less than 9 characters")
    if len(name) < 1:
        raise Exception("Name must not be empty")
    m = re.match("^[0-9a-zA-Z\ ]{1,8}$", name)  # noqa: W605
    if not m:
        raise Exception("Name must consist of combinations of: a-z, A-Z, 0-9")
    return name


def validate_coap_address(addr: str) -> str:
    m = re.match("^coap://[0-9a-zA-Z\.:]+$", addr)  # noqa: W605
    if not m:
        raise Exception("Invalid value provided")
    return addr


def regex_validator(value: str, regex: str) -> Union[bool, str]:
    m = re.match(regex, value)
    if not m:
        raise Exception("Invalid value provided")
    return value


validate_ipv4_slash_notation = partial(regex_validator,
                                       regex="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(3[0-2]|2[0-9]|1[0-9]|[0-9])$")  # noqa: E501, W605

validate_ipv4 = partial(regex_validator,
                        regex="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")  # noqa: E501, W605

validate_mac_address = partial(regex_validator,
                               regex="^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"
                               )


def validate_io_dir(io: str) -> str:
    if str.lower(io) not in ["i", "o"]:
        raise Exception()
    return str.lower(io)


def validate_device_id(id_: str) -> int:
    if int(id_) < 1 or int(id_) > 0x7ff7:
        raise Exception()
    return int(id_)


def validate_comms_timeout(comms: str) -> int:
    if (int(comms) < 50) or (int(comms) > 10000):
        raise Exception()
    return int(comms)


def validate_scramble_key(key: str) -> str:
    m = re.match("^0x[0-9a-fA-F]{8}$", key)
    if not m:
        raise Exception()
    return key


def validate_boolean(boolstr: str) -> str:
    bs = boolstr.lower()
    if bs in ["true", "t"]:
        return True
    elif bs in ["false", "f"]:
        return False
    else:
        raise Exception()


def validate_ssid(ssid: str) -> str:
    # TODO Any validation?
    return ssid


def validate_psk(psk: str) -> str:
    # TODO Password Requirement?
    return psk


def validate_ism_serial(serial_path: str) -> str:
    # This should always be /dev/ttySTM7
    if serial_path == "/dev/ttySTM7":
        return serial_path
    else:
        raise Exception()


def validate_ism_radio_id(ism_radio_id: str) -> str:
    # Must be 6 hex bytes (so, 12 hex characters)
    m = re.match("^[0-9a-fA-F]{12}$", ism_radio_id)
    if not m:
        raise Exception()
    return ism_radio_id


def validate_ism_reset_pin(ism_reset_pin: str) -> str:
    # This should always be AP_ISM_RESET_L
    if ism_reset_pin == "AP_ISM_RESET_L":
        return ism_reset_pin
    else:
        raise Exception()


def validate_ism_peer_id(peer_id: str) -> str:
    # Must be 6 hex bytes (so, 12 hex characters)
    m = re.match("^[0-9a-fA-F]{12}$", peer_id)
    if not m:
        raise Exception()
    return peer_id


def validate_ism_port(ism_port: str) -> str:
    # Must be an integer greater than 1024 and less than 49000
    ism_port_as_num = int(ism_port)
    if ism_port_as_num > 1024 and ism_port_as_num < 49000:
        return ism_port
    else:
        raise Exception()


def validate_connection_mode(connection_mode: str) -> str:
    # Must be one of “base”, “tdmabase”, “tdmaremote”, "cw", or "cwmod".
    if connection_mode in ['base', 'tdmabase', 'tdmaremote', 'cw', 'cwmod']:
        return connection_mode
    else:
        raise Exception()


def validate_dhcp(dhcp: str) -> str:
    if dhcp in ['true', 'false']:
        return dhcp
    else:
        raise Exception()


def validate_peer_deletion(deletion_str: str) -> str:
    if str.lower(deletion_str) not in ["delete"]:
        raise Exception()
    return str.lower(deletion_str)


def validate_coapd_mcgroup(multicast_group_str: str) -> str:
    # Must be a valid IP address, and within the multicast address range
    # Multicast address range is 224.0.0.0 - 239.255.255.255
    regex = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"  # noqa: W605
    if re.match(regex, multicast_group_str):
        ipParts = multicast_group_str.split('.')
        if int(ipParts[0]) >= 224 and int(ipParts[0]) <= 239:
            return multicast_group_str
    raise Exception()


def validate_service_restart(restart: str) -> str:
    if str.lower(restart) != "restart":
        raise Exception()
    return str.lower(restart)


def validate_system_reboot(restart: str) -> str:
    if str.lower(restart) != "reboot":
        print("wrong word entered: ", restart)
        raise ValueError('wrong word entered')
    return str.lower(restart)


def validate_journald_filename(journald_filename: str) -> str:
    # TODO Journald filename Requirement?
    return journald_filename


def validate_ism_power(ism_power: str) -> str:
    # The ism power range is from [-20, 27] however there are gaps
    # that will cause errors on configuration.
    # The valid list of configurations are
    # [-20, -15, -10, -5, 0, 2, 5, 8, 11, 14, 17, 20, 23, 27]
    valid_ism_powers = ["-20", "-15", "-10", "-5", "0", "2", "5", "8", "11", "14", "17", "20", "23", "27"]
    if ism_power not in valid_ism_powers:
        raise ValueError(f"{ism_power} is an invalid value. Must be a value in this list "
                         f"{str(valid_ism_powers)}")
    return int(ism_power)


def validate_ism_rf_channel(rf_channel: str) -> str:
    # - US 902-928 MHz supports channels 1-26
    #        (every 1MHz in the range 902-928 MHz)
    # - EU 869 MHz has only 1 channel
    min_ism_rf_channel = 1
    max_ism_rf_channel = 26
    if int(rf_channel) not in range(min_ism_rf_channel, max_ism_rf_channel + 1):
        raise ValueError(f"{rf_channel} out of range. Must be a value from 1-26")
    return int(rf_channel)


def frc_validate_serial_number(serial_num: str) -> str:
    if len(serial_num) > 8:
        raise Exception("Name must be less than 9 characters")
    if len(serial_num) < 1:
        raise Exception("Name must not be empty")
    m = re.match("^[0-9a-zA-Z\ ]{1,8}$", serial_num)  # noqa: W605
    if not m:
        raise Exception("Name must consist of combinations of: a-z, A-Z, 0-9")
    return serial_num


def frc_validate_js_kp_period(period: int) -> int:
    if int(period) not in range(0, 256):
        raise Exception()
    return int(period)


bleRadioMode = {"CENTRAL": b'M', "PERIPHERAL": b'S'}


def frc_validate_radio_mode(mode: str):
    for key, value in bleRadioMode.items():
        if mode == key:
            return value
    raise Exception()


ismRadioMode = {"TDMA_BASE": b'T', "TDMA_REMOTE": b't'}


def frc_validate_ism_mode(mode: str):
    for key, value in ismRadioMode.items():
        if mode == key:
            return value
    raise Exception()


def frc_validate_ble_pair_index(index: str):
    if int(index) in range(0, 10):
        return index


def frc_validate_machine_index(index: str):
    if int(index) in range(0, 10):
        return index
    raise ValueError("Index value is out of range")


def validate_can0_service(can_service: str) -> str:
    allowed_can_services = ["none", "canopen", "j1939"]
    if can_service.lower() in allowed_can_services:
        return can_service.lower()
    raise ValueError(f"{can_service} is an invalid mode for CAN")


def validate_can0_bitrate(can_bitrate: str) -> str:
    allowed_bitrates = ["10000", "20000", "50000", "125000",
                        "250000", "500000", "800000", "1000000"]

    if can_bitrate in allowed_bitrates:
        return can_bitrate

    raise ValueError(f"{can_bitrate} is an invalid bitrate for CAN")


def validate_firmware_update(filePath: str, maxSize: int) -> bool:
    if pathlib.Path(filePath).exists() is False:
        print("File path <", filePath, "> doesn't exist")
        return False
    size = pathlib.Path(filePath).stat().st_size
    if size > maxSize:
        print("File size", size, "excceds maximum allowed size", maxSize)
        return False
    return True


validators = {
    "validate_ipv4_slash_notation": validate_ipv4_slash_notation,
    "validate_ipv4": validate_ipv4,
    "validate_mac_address": validate_mac_address,
    "validate_coap_address": validate_coap_address,
    "validate_peer_name": validate_peer_name,
    "validate_io_dir": validate_io_dir,
    "validate_comms_timeout": validate_comms_timeout,
    "validate_scramble_key": validate_scramble_key,
    "validate_device_id": validate_device_id,
    "validate_boolean": validate_boolean,
    "validate_ssid": validate_ssid,
    "validate_psk": validate_psk,
    "validate_ism_serial": validate_ism_serial,
    "validate_ism_radio_id": validate_ism_radio_id,
    "validate_ism_reset_pin": validate_ism_reset_pin,
    "validate_ism_peer_id": validate_ism_peer_id,
    "validate_ism_port": validate_ism_port,
    "validate_connection_mode": validate_connection_mode,
    "validate_dhcp": validate_dhcp,
    "validate_peer_deletion": validate_peer_deletion,
    "validate_coapd_mcgroup": validate_coapd_mcgroup,
    "validate_service_restart": validate_service_restart,
    "validate_system_reboot": validate_system_reboot,
    "validate_journald_filename": validate_journald_filename,
    "validate_ism_power": validate_ism_power,
    "validate_ism_rf_channel": validate_ism_rf_channel,
    "frc_validate_serial_number": frc_validate_serial_number,
    "frc_validate_js_kp_period": frc_validate_js_kp_period,
    "frc_validate_radio_mode": frc_validate_radio_mode,
    "frc_validate_ism_mode": frc_validate_ism_mode,
    "frc_validate_ble_pair_index": frc_validate_ble_pair_index,
    "validate_can0_service": validate_can0_service,
    "validate_can0_bitrate": validate_can0_bitrate,
    "validate_firmware_update": validate_firmware_update
}


def get_validator(name: str) -> Validator_t:
    return validators.get(name, None)


formatters = {
    "json_str": lambda x: json.loads(x),
    "hexstring": lambda x: bytes.fromhex(str(x)),
    "number": int,
    "radioMode": lambda x: radioMode(x.encode()).name,
    "ismAddr": IsmAddr.parse,
    "hex": lambda x: hex(int(x)).upper(),
    "frcMode": lambda x: FrcMode(x.encode()).name,
    "temperature": lambda x: f'{int(x)}\u00B0C',
    # 32-bit signed conversion from string int value
    "temperature_32s": lambda x: f'{(int(x) & 0x7fffffff) - (int(x) & 0x80000000)}\u00B0C',
    "string": str,
    "bytearray": lambda x: x.hex()
}


def get_data_formatter_types():
    return formatters.keys()


def get_data_formatter(name: str):
    """display formatters for endpoints that have a text/plain content type"""
    return formatters.get(name, str)
