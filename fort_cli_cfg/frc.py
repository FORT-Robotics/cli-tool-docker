import asyncio
import cbor2
from fort_cli_cfg import fast
from fort_cli_cfg.frc_smcu_config_blob import build_frc_blob_file_data
from . import coap
from .validators import validate_ism_power

paired_device_mac_endpoint = "cfg/setup/pairedDeviceMac"
paired_device_name_endpoint = "cfg/setup/pairedDeviceName"


async def config_frc(device, config):
    device_num = list(config['body']['scm2']['NET']['peers'].keys())[0]
    paring_configurations = ["blue0", "eth0", "wlan0", "ism0"]
    config_mode = ""

    # Iterate through peer list to find the appropriate configuration mode
    for mode in paring_configurations:
        if config['body']['scm2']['NET']['peers'][device_num][mode] is not None:
            config_mode = mode

    if config_mode == "":
        raise ValueError("Error: Unable to determine pairing configuration")

    if config_mode == "blue0":
        await frc_ble_config(device, config)
    if config_mode == "ism0":
        await frc_ism_config(device, config)


async def frc_ble_config(device, config):
    # Set BLE slave mode
    print("Configuring FRC in BLE mode")
    await coap.post(
        device, "cfg/setup/radioMode", b'S', content_format=coap.ContentFormat.TextPlain
    )

    print("Clearing existing machine select table")
    # Must clear the existing machine select table.
    max_device_for_machine_select = 10
    dummy_mac_address = "00:00:00:00:00:00"
    dummy_peer_name = ""
    for device_idx in range(max_device_for_machine_select):
        await asyncio.sleep(.1)
        await coap.post(
            device, paired_device_mac_endpoint, query=f'{device_idx}', payload=dummy_mac_address.encode(),
            content_format=coap.ContentFormat.TextPlain
        )

        await asyncio.sleep(.1)
        await coap.post(
            device, paired_device_name_endpoint, query=f'{device_idx}', payload=dummy_peer_name.encode(),
            content_format=coap.ContentFormat.TextPlain
        )

    # The max device name length is defined by the NSC firmware
    max_name_length = 30
    num_of_peers = len(list(config['body']['scm2']['NET']['peers'].keys()))
    # Populate machine select according to web configuration
    for idx in range(num_of_peers):
        peer_num = list(config['body']['scm2']['NET']['peers'].keys())[idx]
        peer_mac = fast.get_peer_mac(config, peer_num)
        peer_name = config['body']['scm2']['NET']['peers'][str(peer_num)]['name']
        if len(peer_name) > max_name_length:
            peer_name = peer_name[:max_name_length]
        print("Setting index {} peer mac {} peer name {}".format(idx, peer_mac, peer_name))

        # Posting the peer's device mac address
        await asyncio.sleep(.1)
        await coap.post(
            device, paired_device_mac_endpoint, query=f'{idx}', payload=peer_mac.encode(),
            content_format=coap.ContentFormat.TextPlain
        )

        # Posting the peer's device name
        await asyncio.sleep(.1)
        await coap.post(
            device, paired_device_name_endpoint, query=f'{idx}', payload=peer_name.encode(),
            content_format=coap.ContentFormat.TextPlain
        )

    # Currently, using defaults from the build_frc_blob_file_data() function. These can eventually be pulled from
    # cloud-config
    print("Building FRC blob file data")
    config_blob_data = build_frc_blob_file_data()

    await asyncio.sleep(.1)
    await coap.post_blockwise(
        device, 'fl/smcuSettings/data',
        config_blob_data, content_format=coap.ContentFormat.OctetStream
    )


async def frc_ism_config(device, config):
    print("Configuring FRC in ISM mode")

    # In order for machine select to work with the current Fort Manager config file, the network_id
    # needs to be unique, which is why we are using the radio_id as the network_id.
    # This will need to change once the Fort Manager config file has been updated.
    network_id = str(config['body']['scm2']['NET']['ism0']['radio_id'])
    own_id = str(config['body']['scm2']['NET']['ism0']['radio_id'])
    own_addr = network_id + "," + own_id + ",0"
    radio_mode = config['body']['scm2']['NET']['ism0']['connMode']
    radio_power = config['body']['scm2']['NET']['ism0']['txpwr']
    radio_channel = config['body']['scm2']['NET']['ism0']['txChannel']

    mode_setting = b''
    if radio_mode == "Remote":
        mode_setting = b'S'
    elif radio_mode == "Base":
        mode_setting = b'M'
    elif radio_mode == "TDMA-Base":
        mode_setting = b'T'
    elif radio_mode == "TDMA-Remote":
        mode_setting = b't'
    else:
        raise ValueError("ERROR: Unable to determine ISM Radio Mode")
    # This is always setting the FRC to be a TDMA-Base device
    mode_setting = b'T'

    # Set Radio Mode
    print("Setting Radio Mode: TDMA-Base")
    await coap.post(device, "cfg/setup/ism/mode", mode_setting,
                    content_format=coap.ContentFormat.TextPlain)
    await asyncio.sleep(.1)

    # Set ism own addr
    print(f"Setting ISM addresses: {own_addr}")
    await coap.post(device, "cfg/setup/ism/ownAddr", own_addr.encode(),
                    content_format=coap.ContentFormat.TextPlain)
    await asyncio.sleep(.1)

    # Clear machine select table
    print("Clearing existing machine select table")
    max_device_for_machine_select = 10
    dummy_peer_name = ""
    for device_idx in range(max_device_for_machine_select):
        await coap.post(
            device, paired_device_name_endpoint, query=f'{device_idx}', payload=dummy_peer_name.encode(),
            content_format=coap.ContentFormat.TextPlain
        )
        await asyncio.sleep(.1)

    # The max device name length is defined by the NSC firmware
    max_name_length = 30
    num_of_peers = len(list(config['body']['scm2']['NET']['peers'].keys()))
    # Populate machine select according to web configuration
    for idx in range(num_of_peers):
        peer_num = str(list(config['body']['scm2']['NET']['peers'].keys())[idx])
        peer_name = config['body']['scm2']['NET']['peers'][peer_num]['name']
        peer_id = str(config['body']['scm2']['NET']['peers'][peer_num]['ism0'])
        peer_addr = str(peer_id) + "," + str(peer_id) + ",0"
        if len(peer_name) > max_name_length:
            peer_name = peer_name[:max_name_length]

        # Set machine select device names
        await coap.post(
            device, paired_device_name_endpoint,
            query=f'{idx}', payload=peer_name.encode(),
            content_format=coap.ContentFormat.TextPlain
        )
        await asyncio.sleep(.1)

        # Set ism peer addr
        print(f"Setting Peer {idx} address: {peer_addr}")
        await coap.post(
            device, "cfg/setup/ism/pairAddr",
            query=f'{idx}', payload=peer_addr.encode(),
            content_format=coap.ContentFormat.TextPlain
        )
        await asyncio.sleep(.1)

    # Set Radio Power
    print(f"Setting radio power: {radio_power}")
    try:
        radio_power = validate_ism_power(radio_power)
    except ValueError as err:
        raise ValueError(f"ValueError: {err}")

    await coap.post(device, "cfg/setup/radioPower",
                    cbor2.dumps({"radio_power": radio_power}),
                    content_format=coap.ContentFormat.CBOR)
    await asyncio.sleep(.1)

    # Setting RF Channel
    print(f"Settting RF Channel: {radio_channel}")
    await coap.post(device, "cfg/setup/radioChannel",
                    cbor2.dumps({"radio_channel": radio_channel}),
                    content_format=coap.ContentFormat.CBOR)
    await asyncio.sleep(.1)

    # Setting SMCU config blob
    print("Building FRC blob file data")
    config_blob_data = build_frc_blob_file_data()
    await asyncio.sleep(.5)
    await coap.post_blockwise(device, "fl/smcuSettings/data", config_blob_data,
                              content_format=coap.ContentFormat.OctetStream)
    await asyncio.sleep(.1)
