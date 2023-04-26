import pathlib

from .. import coap
from ..core import Menu, SingleRoEndpointWithType, SingleRwEndpointWithType, SingleWoEndpointWithType, \
    FileMenu, SingleRwEndpointWithFakeCBORType, IsmAddressRwEndpoint, SingleRoEndpoint
from ..validators import frc_validate_serial_number, validate_mac_address, frc_validate_ble_pair_index, \
    frc_validate_radio_mode, validate_ism_rf_channel, frc_validate_ism_mode, validate_ism_power, \
    frc_validate_js_kp_period
from ..validators import get_data_formatter

# fully type-checked and statically analyzed version of the endpoints JSON struct
frc_endpoints = Menu(
    name='FRC Config Utility',
    back_text='Quit',
    endpoints=[
        SingleRwEndpointWithType(
            name='Device serial number',
            endpoint='cfg/setup/serialNumber',
            validator=frc_validate_serial_number,
            content_format=coap.ContentFormat.TextPlain
        ),
        SingleRoEndpointWithType(
            name='Device firmware version',
            endpoint='cfg/setup/fwVersion',
            content_format=coap.ContentFormat.TextPlain
        ),
        SingleRoEndpointWithType(
            name='CPU temperature',
            endpoint='cfg/setup/cpuTemp',
            content_format=coap.ContentFormat.TextPlain,
            data_formatter=get_data_formatter('temperature')
        ),
        SingleWoEndpointWithType(
            name='Device reboot',
            endpoint='cfg/setup/systemReset',
            content_format=coap.ContentFormat.TextPlain,
            value='n'
        ),
        SingleWoEndpointWithType(
            name='Device reboot into bootloader',
            endpoint='cfg/setup/systemReset',
            content_format=coap.ContentFormat.TextPlain,
            value='b'
        ),
        FileMenu(
            name='Device firmware',
            endpoint='fl/updateAppImg',
            file_path=pathlib.Path('devFirmware.bin')
        ),
        Menu(
            name='BLE Config',
            endpoints=[
                SingleRoEndpoint(
                    name='MAC address',
                    endpoint='cfg/setup/deviceMac'
                ),
                SingleRwEndpointWithType(
                    name='Pair MAC address',
                    endpoint='cfg/setup/pairedDeviceMac',
                    validator=validate_mac_address,
                    content_format=coap.ContentFormat.TextPlain
                ),
                SingleRwEndpointWithType(
                    name='Pair MAC index',
                    endpoint='cfg/setup/pairedMacIndex',
                    validator=frc_validate_ble_pair_index,
                    content_format=coap.ContentFormat.TextPlain,
                    data_formatter=get_data_formatter('number')
                ),
                SingleRwEndpointWithType(
                    name='Radio mode',
                    endpoint='cfg/setup/radioMode',
                    validator=frc_validate_radio_mode,
                    content_format=coap.ContentFormat.TextPlain,
                    data_formatter=get_data_formatter('radioMode')
                ),
                FileMenu(
                    name='Radio Firmware',
                    endpoint='fl/radiofw',
                    file_path=pathlib.Path('radioFirmware.bin'),
                    file_info_endpoint='cfg/radiofw/expectedCrc'
                )
            ]
        ),
        Menu(
            name='ISM Config',
            endpoints=[
                SingleRwEndpointWithFakeCBORType(
                    name='Radio channel',
                    endpoint='cfg/setup/radioChannel',
                    validator=validate_ism_rf_channel
                ),
                SingleRwEndpointWithType(
                    name='Radio mode',
                    endpoint='cfg/setup/ism/mode',
                    validator=frc_validate_ism_mode,
                    content_format=coap.ContentFormat.TextPlain,
                    data_formatter=get_data_formatter('radioMode')
                ),
                SingleRwEndpointWithFakeCBORType(
                    name='Radio power',
                    endpoint='cfg/setup/radioPower',
                    validator=validate_ism_power
                ),
                IsmAddressRwEndpoint(
                    name='Own address',
                    endpoint='cfg/setup/ism/ownAddr',
                    validator=lambda x: True,  # TODO: frc_validate_ism_addr was never actually implemented
                    content_format=coap.ContentFormat.TextPlain,
                    data_formatter=get_data_formatter('ismAddr')
                ),
                IsmAddressRwEndpoint(
                    name='Pair address',
                    endpoint='cfg/setup/ism/pairAddr',
                    validator=lambda x: True,  # TODO: frc_validate_ism_pair_addr was never actually implemented
                    content_format=coap.ContentFormat.TextPlain,
                    data_formatter=get_data_formatter('ismAddr')
                ),
                FileMenu(
                    name='Radio Firmware',
                    endpoint='fl/ismfw',
                    file_path=pathlib.Path('radioFirmware.bin'),
                    file_info_endpoint='cfg/ismfw/expectedCrc'
                )
            ]
        ),
        Menu(
            name='Joystick information',
            endpoints=[
                SingleRwEndpointWithFakeCBORType(
                    name='Period',
                    endpoint='st/joystick/period',
                    validator=frc_validate_js_kp_period,
                ),
                SingleRoEndpointWithType(
                    name='Status',
                    endpoint='st/joystick',
                    content_format=coap.ContentFormat.CBOR
                )
            ]
        ),
        Menu(
            name='Keypad information',
            endpoints=[
                SingleRwEndpointWithFakeCBORType(
                    name='Period',
                    endpoint='st/keypad/period',
                    validator=frc_validate_js_kp_period,
                ),
                SingleRoEndpointWithType(
                    name='Status',
                    endpoint='st/keypad',
                    content_format=coap.ContentFormat.CBOR
                )
            ]
        ),
        FileMenu(
            name='SMCU settings',
            endpoint='fl/smcuSettings',
            file_path=pathlib.Path('smcuSettings.blob')
        ),
        SingleRoEndpointWithType(
            name='FRC mode',
            endpoint='st/mode',
            content_format=coap.ContentFormat.TextPlain,
            data_formatter=get_data_formatter('frcMode')
        )
    ])
