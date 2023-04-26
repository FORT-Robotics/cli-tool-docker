from .validators import (validate_can0_bitrate, validate_can0_service, get_validator,
                         validate_ism_power, validate_ism_rf_channel, uint16)


def validate_device_type(device_type: str):
    if device_type not in ['EPC', 'FRC', 'NSC']:
        raise ValueError(f"{device_type} is an invalid device_type")
    return device_type


def validate_io_direction_value(io_direction: str):
    if io_direction not in ['Out', 'In']:
        raise ValueError(f"{io_direction} is an invalid I/O direction type")
    return io_direction


def validate_safety_rate(safety_rate: int):
    if safety_rate not in [25, 50]:
        raise ValueError(f"{safety_rate} is an invalid safety rate. Must be either 25ms or 50ms")
    return safety_rate


def validate_safety_timeout(timeout: int):
    if timeout < 250 or timeout > 2000:
        raise ValueError(f"{timeout} is an invalid safety timeout. Must be between 250 ms and 2000 ms.")
    return timeout


def validate_ism_connection_mode(mode_setting: str):
    if mode_setting not in ['Remote', 'Base', 'TDMA-Base', 'TDMA-Remote']:
        raise ValueError(f"{mode_setting} is an invalid connection mode setting")
    return mode_setting


# Gateway can be either none or a valid ip address
def validate_gateway_value(gateway: str):
    ip_validator = get_validator("validate_ipv4")
    if gateway is not None:
        ip_validator(gateway)

    return gateway


def validate_two_byte_value_excluding_zero(value: int):
    if value == 0:
        raise ValueError("Invalid value of zero")
    else:
        uint16(value)
    return value


def validate_bool_type(data):
    if type(data) != bool:
        raise TypeError("Invalid data type. Type must be a boolean.")
    return data


def validate_string_type(data):
    if type(data) != str:
        raise TypeError("Invalid data type. Type must be a string.")
    return data


class FortManagerConfigValidator:
    def __init__(self, config_blob):
        self.__config = config_blob

    def validate(self) -> bool:
        return self.__validate_structure() and self.__validate_data()

    def __validate_structure(self) -> bool:
        return self.__validate_own_network_interface() and self.__validate_peer_network_interface()

    def __validate_data(self) -> bool:
        if (not self.__validate_net_fields() or not
                self.__validate_net_peers_fields() or not
                self.__validate_safe_fields()):
            return False
        return True

    # There can only be one network interface. More than one is an invalid configuration
    def __validate_own_network_interface(self) -> bool:
        num_interfaces = 0
        net_fields = self.__config['body']['scm2']['NET']
        for interface in ['blue0', 'ism0', 'eth0', 'wlan0']:
            if net_fields[interface] is not None:
                num_interfaces += 1
        if num_interfaces != 1:
            print(f"Invalid Configuration: {num_interfaces} is an invalid number of interfaces")
            return False
        return True

    # There can only be one network interface for the peer. More than one is an invalid configuration
    def __validate_peer_network_interface(self) -> bool:
        peers = self.__config['body']['scm2']['NET']['peers']
        for peer in peers:
            num_interfaces = 0
            for interface in ['blue0', 'ism0', 'eth0', 'wlan0']:
                if peers[peer][interface] is not None:
                    num_interfaces += 1
            if num_interfaces != 1:
                print(f"Invalid Configuration: {num_interfaces} is an invalid number of peer interfaces")
                return False
        return True

    def __validate_net_fields(self) -> bool:
        results = True
        net_fields = self.__config['body']['scm2']['NET']
        if net_fields['blue0'] is not None:
            results = results and self.__validate_ble_values(net_fields['blue0'])
        elif net_fields['ism0'] is not None:
            results = results and self.__validate_ism_values()
        elif net_fields['eth0'] is not None:
            results = results and self.__validate_eth_values()
        elif net_fields['wlan0'] is not None:
            results = results and self.__validate_wlan_values()
        else:
            raise ValueError("Fort Manager Configuration is not properly setting the interface mode")
        results = results and self.__validate_can_values()
        return results

    def __validate_net_peers_fields(self) -> bool:
        peers_fields = self.__config['body']['scm2']['NET']['peers']
        results = True
        for peer in peers_fields:
            device_id = peers_fields[peer]['deviceId']
            device_name = peers_fields[peer]['name']
            device_type = peers_fields[peer]['deviceType']

            try:
                validate_two_byte_value_excluding_zero(device_id)
                validate_device_type(device_type)
                validate_string_type(device_name)
            except (ValueError, TypeError) as e:
                print(f"Peer Validator failed: {e}")
                return False

            # Find peer interface type
            if peers_fields[peer]['blue0'] is not None:
                results = self.__validate_ble_values(peers_fields[peer]['blue0'])
            elif peers_fields[peer]['ism0'] is not None:
                results = self.__validate_ism_peer_values(peers_fields[peer]['ism0'])
            elif peers_fields[peer]['eth0'] is not None:
                results = self.__validate_eth_peer_values(peers_fields[peer]['eth0'])
            elif peers_fields[peer]['wlan0'] is not None:
                results = self.__validate_wlan_peer_values(peers_fields[peer]['wlan0'])
            if not results:
                return False

        return results

    def __validate_safe_fields(self) -> bool:
        safe_fields = self.__config['body']['scm2']['SAFE']
        io_direction = safe_fields['ioDirection']
        safety_timeout = safe_fields['safetyTimeout']
        device_id = safe_fields['deviceId']
        care_id_array = safe_fields['careId']
        safety_rate = safe_fields['safetyRate']
        safety_rate_threshold = safety_timeout / 10

        try:
            uint16(device_id)
            for care_id in care_id_array:
                uint16(care_id)
            validate_safety_rate(safety_rate)
            validate_safety_timeout(safety_timeout)
            validate_io_direction_value(io_direction)
        except Exception as e:
            print(f"SAFE Validator failed: {e}")
            return False

        # Checking that the safety rate value is atleast 10 times smaller than the timeout
        if any([safety_rate <= 0,
                safety_rate_threshold <= 0,
                safety_rate > safety_rate_threshold]):
            print("SAFE Validator failed: Invalid Safety values")
            return False

        return True

    def __validate_ble_values(self, ble_fields) -> bool:
        mac = ble_fields['mac']
        try:
            mac_validator = get_validator("validate_mac_address")
            mac_validator(mac)
        except Exception as e:
            print(f"BLE Validator failed: {e}")
            return False
        return True

    def __validate_ism_values(self) -> bool:
        radio_id = self.__config['body']['scm2']['NET']['ism0']['radio_id']
        network_id = self.__config['body']['scm2']['NET']['ism0']['network_id']
        tx_pwr = self.__config['body']['scm2']['NET']['ism0']['txpwr']
        tx_channel = self.__config['body']['scm2']['NET']['ism0']['txChannel']
        con_mode = self.__config['body']['scm2']['NET']['ism0']['connMode']

        try:
            validate_two_byte_value_excluding_zero(radio_id)
            validate_two_byte_value_excluding_zero(network_id)
            validate_ism_power(tx_pwr)
            validate_ism_rf_channel(tx_channel)
            validate_ism_connection_mode(con_mode)

        except Exception as e:
            print(f"ISM Validator failed: {e}")
            return False

        return True

    def __validate_ism_peer_values(self, ism_radio_id) -> bool:
        try:
            validate_two_byte_value_excluding_zero(ism_radio_id)
        except Exception as e:
            print(f"ISM Peer Validator failed: {e}")
            return False
        return True

    def __validate_eth_values(self) -> bool:
        eth_configs = self.__config['body']['scm2']['NET']['eth0']
        ip4_address = eth_configs['ip4']
        netmask = eth_configs['netmask4']
        gateway = eth_configs['gateway4']
        dns_servers = eth_configs['nameservers4']
        is_dhcp = eth_configs['isDHCP']

        try:
            ip_validator = get_validator("validate_ipv4")
            ip_validator(ip4_address)
            ip_validator(netmask)
            validate_gateway_value(gateway)
            for server in dns_servers:
                ip_validator(server)
            validate_bool_type(is_dhcp)

        except Exception as e:
            print(f"Eth Validator failed: {e}")
            return False

        return True

    def __validate_eth_peer_values(self, ip_address):
        ip_validator = get_validator("validate_ipv4")
        try:
            ip_validator(ip_address['ip4'])
        except Exception as e:
            print(f"Eth Peer Validator failed: {e}")
            return False
        return True

    def __validate_wlan_values(self) -> bool:
        wifi_configs = self.__config['body']['scm2']['NET']['wlan0']
        ssid = wifi_configs['ssid']
        ssid_pwd = wifi_configs['ssidPwd']
        wpa_supplicant_en = wifi_configs['wpa_supplicantEn']
        hostapd_en = wifi_configs['hostapdEn']
        ip4_address = wifi_configs['ip4']
        netmask = wifi_configs['netmask4']
        gateway = wifi_configs['gateway4']
        dns_servers = wifi_configs['nameservers4']
        is_dhcp = wifi_configs['isDHCP']
        ip_validator = get_validator('validate_ipv4')

        try:
            validate_string_type(ssid)
            validate_string_type(ssid_pwd)
            validate_bool_type(wpa_supplicant_en)
            validate_bool_type(hostapd_en)
            ip_validator(ip4_address)
            ip_validator(netmask)
            validate_gateway_value(gateway)
            for server in dns_servers:
                ip_validator(server)
            validate_bool_type(is_dhcp)

        except Exception as e:
            print(f"Wlan Validator failed: {e}")
            return False

        return True

    def __validate_wlan_peer_values(self, ip_address):
        ip_validator = get_validator("validate_ipv4")
        try:
            ip_validator(ip_address['ip4'])
        except Exception as e:
            print(f"Wlan Validator failed: {e}")
            return False

        return True

    def __validate_can_values(self) -> bool:
        can_data = self.__config['body']['scm2']['NET']['can0']
        bitrate = str(can_data['bitrate'] * 1000)
        can_mode = can_data['mode']
        if can_mode == "Disabled":
            can_mode = "none"
        try:
            validate_can0_bitrate(bitrate)
            validate_can0_service(can_mode)
        except Exception as e:
            print(f"CAN Validator failed: {e}")
            return False

        return True
