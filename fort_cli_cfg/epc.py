import asyncio
import json
import pathlib

from . import coap
from . import fast
from .validators import validate_ism_power


async def epc_post(device, path, value):
    """handle epc post format, which requires posting a json blob to the parent of the endpoint"""
    ppath = pathlib.PosixPath(path)
    return await coap.post_json(device, f'{ppath.parent}', {ppath.name: value})


async def set_ble_peer_mac_is_server_config(device, mac, is_server: bool):
    print(f"Setting pair MAC address {mac}")
    await asyncio.sleep(.1)
    response = await coap.post_json(device, 'cfg/net/ble0',
                                    {'pairMac': mac, 'isServer': is_server})

    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting pair MAC address: response={}".format(response))


async def set_peer_observables_all(device):
    obsv_cfg = [
        {
            "observeType": "directForward",
            "targetTopic": [
                "/sf/0/to",
                "/sf/1/to"
            ],
            "toObserve": "/sf/0/s"
        },
        {
            "observeType": "directForward",
            "targetTopic": [
                "/sf/0/to",
                "/sf/1/to"
            ],
            "toObserve": "/sf/1/s"
        },
        {
            "observeType": "directForward",
            "targetTopic": ["/st/keypad"],
            "toObserve": "/st/keypad"
        },
        {
            "observeType": "directForward",
            "targetTopic": ["/st/joystick/calibrated"],
            "toObserve": "/st/joystick/calibrated"
        }
    ]
    # Encode the JSON as an escaped string, while dropping the outermost '"'
    # marks
    obsv_cfg = json.dumps(json.dumps(obsv_cfg))[1:-1]

    # Specify the peer endpoints for observation
    print("Applying observables configuration")
    await asyncio.sleep(.1)
    response = await coap.post_json(device, 'cfg/peers/peer0', {'obsv': obsv_cfg})
    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting EPC observables configuration: response={}".format(response))


async def set_peer_observables_default(device):
    obsv_cfg = [
        {
            "observeType": "directForward",
            "targetTopic": [
                "/sf/0/to",
                "/sf/1/to"
            ],
            "toObserve": "/sf/0/s"
        },
        {
            "observeType": "directForward",
            "targetTopic": [
                "/sf/0/to",
                "/sf/1/to"
            ],
            "toObserve": "/sf/1/s"
        },
    ]
    # Encode the JSON as an escaped string, while dropping the outermost '"'
    # marks
    obsv_cfg = json.dumps(json.dumps(obsv_cfg))[1:-1]

    # Specify the peer endpoints for observation
    print("Applying observables configuration")
    await asyncio.sleep(.1)
    response = await coap.post_json(device, 'cfg/peers/peer0', {'obsv': obsv_cfg})
    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting EPC observables configuration: response={}".format(response))


async def set_ble_peer_config(device):
    print("Setting peer address: coap://127.0.0.1:12000")
    await asyncio.sleep(.1)
    response = await coap.post_json(device, 'cfg/peers/peer0', {'addr': 'coap://127.0.0.1:12000'})
    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting peer address: response={}".format(response))

    await set_peer_observables_all(device)


async def set_ism_peer_config(device):
    print("Setting peer address: coap://127.0.0.1:12345")
    await asyncio.sleep(.1)
    response = await coap.post_json(device, 'cfg/peers/peer0', {'addr': 'coap://127.0.0.1:12345'})
    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting peer address: response={}".format(response))

    await set_peer_observables_all(device)


async def set_wifi_or_eth_peer_config(device, ip_addr: str, name):
    full_addr = "coap://" + ip_addr
    print(f"Setting Peer config: {full_addr}")
    await asyncio.sleep(.1)
    response = await coap.post_json(device, 'cfg/peers/peer0', {'addr': full_addr})
    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting peer address: response={}".format(response))

    await asyncio.sleep(.1)
    response = await coap.post_json(device, 'cfg/peers/peer0', {'name': name})

    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting peer address: response={}".format(response))

    await set_peer_observables_default(device)


async def delete_peer_zero_config(device):
    print("Deleting Peer 0")
    # Delete peer zero config
    await asyncio.sleep(.1)
    response = await coap.post_json(device, "cfg/peers/peer0",
                                    {'addr': '', 'name': '', 'obsv': '[]'})
    if not response or not response.code.is_successful():
        raise coap.ClientException("Error deleting peer address 0: response={}".format(response))


async def set_wlan0_addr(device, ip_addr: str, sub_net_mask: str):
    bit_count = 0
    bit_mask = 0x01

    # Count the number of 1 bits in the subnet mask:
    for item in sub_net_mask.split('.'):
        int_item = int(item)
        for i in range(8):
            if bit_mask & (int_item >> i):
                bit_count += 1

    full_addr = ip_addr + "/" + str(bit_count)
    print("Setting WLAN IP address: {full_addr}")
    await asyncio.sleep(.1)
    response = await coap.post_json(device, 'cfg/net/wlan0', {'ip': full_addr})
    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting wlan0 address: response={}".format(response))


async def set_eth_ip_addr(device, ip_addr: str, sub_net_mask: str):
    bit_count = 0
    bit_mask = 0x01

    # Count the number of 1 bits in the subnet mask:
    for item in sub_net_mask.split('.'):
        int_item = int(item)
        for i in range(8):
            if bit_mask & (int_item >> i):
                bit_count += 1

    full_addr = ip_addr + "/" + str(bit_count)
    print("Setting ETH IP Address: {full_addr}")

    await asyncio.sleep(.1)
    response = await coap.post_json(device, 'cfg/net/eth0/port0', {'ip': full_addr})
    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting wlan0 address: response={}".format(response))


async def set_is_client_is_server_config(device, is_client: bool, is_server: bool):
    print("Setting WiFi client and server configs")
    await asyncio.sleep(.1)
    response = await coap.post_json(device, 'cfg/net/wlan0',
                                    {'isClient': is_client, 'isServer': is_server})
    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting client and server config: response={}".format(response))


async def set_ssid_and_psk_config(device, ssid, psk):
    print("Setting ssid and psk: {ssid}")
    await asyncio.sleep(.1)
    response = await coap.post_json(device, 'cfg/net/wlan0',
                                    {'clientSSID': ssid, 'clientPsk': psk})
    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting ssid and psk: response={}".format(response))


async def set_epc_as_output_device(device):
    print("Configuring EPC as output device")
    await asyncio.sleep(.1)
    response = await coap.post_json(
        device,
        'cfg/sf/smcu/global',
        {
            'firmware': '/usr/lib/smcu/dev_out/ER_RO',
            'firmwareCrcs': '/usr/lib/smcu/dev_out/ER_FS',
            'optionBytes': '/usr/lib/smcu/dev_out/ER_OPT_BYTES'
        }
    )
    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting EPC as output device: response={}".format(response))


async def set_epc_as_input_device(device):
    print("Configuring EPC as Input device")
    await asyncio.sleep(.1)
    response = await coap.post_json(
        device,
        'cfg/sf/smcu/global',
        {
            'firmware': '/usr/lib/smcu/dev_in/ER_RO',
            'firmwareCrcs': '/usr/lib/smcu/dev_in/ER_FS',
            'optionBytes': '/usr/lib/smcu/dev_in/ER_OPT_BYTES'
        }
    )
    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting EPC as input device: response={}".format(response))


async def set_smcu_settings_config(device, device_id: str, care_id: str):
    smcu_settings = {
        'cfg/sf/smcu/global/timeoutMs': '500',
        'cfg/sf/smcu/global/txRateMs': '50',
        'cfg/sf/smcu/smcu0/txkey': '0x11223344',
        'cfg/sf/smcu/smcu1/txkey': '0x11223344',
        'cfg/sf/smcu/care0/smcu0key': '0x11223344',
        'cfg/sf/smcu/care0/smcu1key': '0x11223344',
        'cfg/sf/smcu/global/deviceId': device_id,
        'cfg/sf/smcu/care0/deviceId': care_id,
    }

    print("Setting SMCU blob")
    for path, value in smcu_settings.items():
        await asyncio.sleep(.1)
        resp = await epc_post(device, path, value)
        if not resp or not resp.code.is_successful():
            raise coap.ClientException("POST Error, path={}, value={}".format(path, value))


async def set_can_configuration_settings(device, config):
    can_bitrate = config['body']['scm2']['NET']['can0']['bitrate']
    can_bitrate = can_bitrate * 1000
    can_mode = config['body']['scm2']['NET']['can0']['mode']
    if can_mode == "Disabled":
        can_mode = "none"

    print(f"Applying CAN configuration settings - bitrate:{can_bitrate}, mode:{can_mode}")
    await asyncio.sleep(.1)
    response = await coap.post_json(device, 'cfg/net/can0/canBitrate', str(can_bitrate))

    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting can configuration: response={}".format(response))

    await asyncio.sleep(.1)
    response = await coap.post_json(device, 'cfg/net/can0/canService', can_mode)

    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting can configuration: response={}".format(response))


async def set_ism_connection_setting(device):
    mode_setting = "tdmaremote"
    print("Configuring ism connection to TDMA-Remote")
    await asyncio.sleep(.1)
    response = await coap.post_json(device, "cfg/radio/ism0/connectionMode",
                                    mode_setting)
    if not response or not response.code.is_successful():
        raise coap.ClientException("Error setting the connection mode: response={}".format(response))


async def set_ism_power_and_channel(device, config):
    ism_power = config['body']['scm2']['NET']['ism0']['txpwr']
    radio_channel = config['body']['scm2']['NET']['ism0']['txChannel']
    print(f"Configuring epc for ism power {ism_power} and radio channel {radio_channel}")

    # Set ism power
    await asyncio.sleep(.1)
    try:
        ism_power = validate_ism_power(ism_power)
    except ValueError as err:
        raise ValueError(f"ValueError: {err}")

    response = await coap.post_json(device, "cfg/radio/ism0/power", ism_power)
    if not response or not response.code.is_successful():
        raise coap.ClientException(f"Error setting the ism radio power: response={response}")

    # Set rf channel
    await asyncio.sleep(.1)
    response = await coap.post_json(device, "cfg/radio/ism0/rfChannel", radio_channel)
    if not response or not response.code.is_successful():
        raise coap.ClientException(f"Error setting the rf channel: response={response}")


async def set_radio_ids(device, config):
    max_id_value = 255

    # In order for machine select to work with the current Fort Manager config file, the network_id
    # needs to be unique, which is why we are using the radio_id as the network_id.
    # This will need to change once the Fort Manager config file has been updated.
    network_id = config['body']['scm2']['NET']['ism0']['radio_id']
    radio_id = config['body']['scm2']['NET']['ism0']['radio_id']
    peer_num = str(list(config['body']['scm2']['NET']['peers'].keys())[0])
    peer_radio_id = config['body']['scm2']['NET']['peers'][peer_num]['ism0']

    # Check to make sure the id values exceed the required value
    if network_id > max_id_value or radio_id > max_id_value or peer_radio_id > max_id_value:
        raise ValueError("Error id value exceeds 255")

    # The coap endpoint's value, for the ism radio's network id and radio id, is a hex string
    # radio/peer id hex string format FF000F000F00
    # drop the "0x" from the hex string of the network_id
    network_id = str(format(network_id, '#04x'))[2:]
    radio_id = str(format(radio_id, '#04x'))[2:]
    peer_radio_id = str(format(peer_radio_id, '#04x'))[2:]
    unused_input_id = '01'
    radio_id_payload = network_id + '00' + radio_id + '00' + unused_input_id + '00'
    peer_id_payload = network_id + '00' + peer_radio_id + '00' + unused_input_id + '00'

    print(f"Setting coap radio id: {radio_id_payload} and coap peer radio id: {peer_id_payload}")
    await asyncio.sleep(.1)
    response = await coap.post_json(device, "cfg/radio/ism0",
                                    {'radioId': radio_id_payload,
                                     'peerId': peer_id_payload})
    if not response or not response.code.is_successful():
        raise coap.ClientException(f"Error setting the radio id: response={response}")


async def clear_care_list(device):
    clear_value = 0xFFFF
    endpoint_prefix = "cfg/sf/smcu/"
    endpoint_key = "/deviceId"

    # Currently support 5 care devices care0 - care4. Note range(0,5) will loop through the values 0-4
    for care_id in range(0, 5):
        care_list_endpoint = endpoint_prefix + f"care{care_id}" + endpoint_key
        response = await coap.post_text(device,
                                        care_list_endpoint,
                                        str(clear_value),
                                        content_format=coap.ContentFormat.TextPlain)

        if not response or not response.code.is_successful():
            raise coap.ClientException(f"Error deleteing care id {care_id}: response={response}")

        await asyncio.sleep(.1)


async def clear_peer_list(device):
    clear_value = {'addr': '', 'name': '', 'obsv': '[]'}
    endpoint_prefix = "cfg/peers/"

    # Currently supports 5 peers devices peer0 - peer4. Note ranger(0,5) will loop through the values 0-4
    for peer_id in range(0, 5):
        peer_endpoint = endpoint_prefix + f"peer{peer_id}"
        response = await coap.post_json(device, peer_endpoint, clear_value)

        if not response or not response.code.is_successful():
            raise coap.ClientException(f"Error deleteing peer address {peer_id}: response={response}")

        await asyncio.sleep(.1)


async def web_config_epc(device: str, config: dict) -> bool:
    device_num = list(config['body']['scm2']['NET']['peers'].keys())[0]
    paring_configurations = ["blue0", "eth0", "wlan0", "ism0"]
    config_mode = ""

    # Iterate through peer list to find the appropriate configuration mode
    for mode in paring_configurations:
        if config['body']['scm2']['NET']['peers'][device_num][mode] is not None:
            config_mode = mode

    if config_mode == "":
        raise ValueError("Error: Unable to determine pairing configuration")

    # Delete all care and peer list entries
    await clear_care_list(device)
    await clear_peer_list(device)

    if config_mode == "blue0":
        await epc_ble_config(device, config)
    elif config_mode == "ism0":
        await epc_ism_config(device, config)
    elif config_mode == "wlan0":
        await epc_wifi_config(device, config)
    elif config_mode == "eth0":
        await epc_eth_config(device, config)


async def epc_ble_config(device: str, config: dict):
    print("Configuring EPC in BLE mode")

    peer_num = list(config['body']['scm2']['NET']['peers'].keys())[0]
    mac = fast.get_peer_mac(config, peer_num)

    # Set Pair MAC and isServer properties
    await set_ble_peer_mac_is_server_config(device, mac, False)

    # Set the peer address
    await set_ble_peer_config(device)

    # Configure EPC safety stack as an output device
    await set_epc_as_output_device(device)

    # loading default SMCU settings for now. These can eventually be extracted from cloud-config
    await set_smcu_settings_config(device, "1", "2")

    # Configure can settings
    await set_can_configuration_settings(device, config)


async def epc_ism_config(device, config):
    print("Configuring EPC in ISM mode")

    # Set the peer address
    await set_ism_peer_config(device)

    # Configure EPC safety stack as an output device
    await set_epc_as_output_device(device)

    # loading default SMCU settings for now. These can eventually be extracted from cloud-config
    await set_smcu_settings_config(device, "1", "2")

    # Configure can settings
    await set_can_configuration_settings(device, config)

    # Configure connection type
    await set_ism_connection_setting(device)

    # Configure ism radio power and transmission channel
    await set_ism_power_and_channel(device, config)

    # Configure ism network id, own radio id, and  peer's radio id
    await set_radio_ids(device, config)


async def epc_wifi_config(device, config):
    print("Configuring EPC in WiFi mode")

    device_i_o = config['body']['scm2']['SAFE']["ioDirection"]
    if device_i_o == "Out":
        peer_num = list(config['body']['scm2']['NET']['peers'].keys())[0]
        peer_ip_addr = config['body']['scm2']['NET']['peers'][peer_num]['wlan0']['ip4']
        ip_addr = config['body']['scm2']['NET']['wlan0']['ip4']
        sub_net_mask = config['body']['scm2']['NET']['wlan0']['netmask4']

        # Set IO Direction
        await set_epc_as_output_device(device)

        # Loading default SMCU settings for now. These can eventually be extracted from cloud-config
        await set_smcu_settings_config(device, "2", "1")

        # Set WLAN settings
        await set_wlan0_addr(device, ip_addr, sub_net_mask)
        await set_wifi_or_eth_peer_config(device, peer_ip_addr, "WIFI EPC")

        await set_is_client_is_server_config(device, True, False)

        ssid = config['body']['scm2']['NET']['wlan0']['ssid']
        psk = config['body']['scm2']['NET']['wlan0']['ssidPwd']

        # Configure SSID and PSK
        await set_ssid_and_psk_config(device, ssid, psk)

        # Configure can settings
        await set_can_configuration_settings(device, config)

    elif device_i_o == "In":
        peer_num = list(config['body']['scm2']['NET']['peers'].keys())[0]
        peer_ip_addr = config['body']['scm2']['NET']['peers'][peer_num]['wlan0']['ip4']
        ip_addr = config['body']['scm2']['NET']['wlan0']['ip4']
        sub_net_mask = config['body']['scm2']['NET']['wlan0']['netmask4']

        # Set IO Direction
        await set_epc_as_input_device(device)

        # Loading default SMCU settings for now. These can eventually be extracted from cloud-config
        await set_smcu_settings_config(device, "1", "2")

        await set_wlan0_addr(device, ip_addr, sub_net_mask)
        await set_wifi_or_eth_peer_config(device, peer_ip_addr, "WIFI EPC")

        # Configure can settings
        await set_can_configuration_settings(device, config)

    else:
        raise ValueError("Error: Unable to determine device IO setting.")


async def epc_eth_config(device, config):
    print("Configuring EPC in Ethernet mode")

    device_i_o = config['body']['scm2']['SAFE']["ioDirection"]
    ip_addr = config['body']['scm2']['NET']['eth0']['ip4']
    sub_net_mask = config['body']['scm2']['NET']['eth0']['netmask4']
    peer_num = str(list(config['body']['scm2']['NET']['peers'].keys())[0])
    peer_ip_addr = config['body']['scm2']['NET']['peers'][peer_num]["eth0"]["ip4"]
    num_of_peers = len(list(config['body']['scm2']['NET']['peers'].keys()))

    # Setting port 0 ip address
    await set_eth_ip_addr(device, ip_addr, sub_net_mask)

    if device_i_o == "Out":
        await set_epc_as_output_device(device)
        await set_smcu_settings_config(device, "2", "1")

        # Setting Peer configuration
        await set_wifi_or_eth_peer_config(device, peer_ip_addr, "ETH EPC")

    elif device_i_o == "In":
        await set_epc_as_input_device(device)
        await set_smcu_settings_config(device, "1", "2")

        # In a 1 to many scenario we delete the input devices peer config
        if num_of_peers > 1:
            # Delete Peer0 config
            await delete_peer_zero_config(device)
        else:
            await set_wifi_or_eth_peer_config(device, peer_ip_addr, "ETH EPC")

    else:
        raise ValueError("Error: Unable to determine device IO settings.")

    # Configure can settings
    await set_can_configuration_settings(device, config)
