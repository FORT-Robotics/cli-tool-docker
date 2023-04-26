import json
from enum import Enum
from typing import Tuple
from urllib.parse import urljoin
from tempfile import NamedTemporaryFile

import requests

from fort_cli_cfg.validators import validate_mac_address


# https://dev.api.fortrobotics.com/doc/swagger/index.html?url=/doc/swagger/spec
# https://fint-api-dev.azurewebsites.net/doc/swagger/index.html?url=/doc/swagger/spec
session_key_str = "SessionKey "


class FmResponseException(Exception):
    pass


class DevType(Enum):
    FRC = 1
    EPC = 3


def get_user_credentials() -> Tuple[str, str]:
    import getpass
    user = input("Enter User ID (email): ")
    pass_ = getpass.getpass()
    return (user, pass_)


def login(uri_root: str, user: str, pass_: str) -> str:
    auth_payload = {"email": user, "password": pass_, "gateToken": "string"}
    auth_url = urljoin(uri_root, "v1/authentication")
    auth_headers = {"accept": "application/json", "Content-Type": "application/json"}
    auth_response = requests.post(auth_url, headers=auth_headers, data=json.dumps(auth_payload))
    auth_rsp = json.loads(auth_response.text)
    token = session_key_str + str(auth_rsp['session'])
    return token


# Individual device configuration
def get_device_config_from_fm(uri_root: str, token: str, device_sn: str):
    dev_url = urljoin(uri_root, "v1/devices/by")

    # Strip Session Key from the JSON string and formatted the
    # response so it is JSON Compatable.
    stripped_token = token[11:]
    stripped_token = stripped_token.replace("'", '"')\
        .replace(" True", ' "True"').replace(" False", ' "False"').replace("None", '""')
    json_token = json.loads(stripped_token)
    dev_headers = {'accept': 'application/json', 'Authorization': session_key_str + json_token["id"]}
    try:
        response = requests.get(
            dev_url, params={'serial': device_sn}, headers=dev_headers
        )
        if response.status_code != 200:
            raise FmResponseException(f"Error fetching device {device_sn} "
                                      f"with reponse {response.status_code}")

        device_data = json.loads(response.text)
        device_uuid = device_data['id']
    except Exception as e:
        raise FmResponseException(f"{e}")

    sync_url = urljoin(uri_root, "v1/devices/{id}/safety-configs/syncs")
    sync_headers = {'accept': 'application/octet-stream',
                    'Authorization': session_key_str + json_token["id"]}

    try:
        sync_response = requests.post(sync_url.format(id=device_uuid), headers=sync_headers)
        if sync_response.status_code != 200:
            raise FmResponseException(f"Error retrieving configuration for device {device_sn}")
        secure_config_content = sync_response.content
    except Exception as e:
        raise FmResponseException(f"{e}")

    # Check to see if tmp directory has already been created
    temp_cbor_filepath = None
    with NamedTemporaryFile(suffix=".cbor", delete=False) as named_tempfile:
        named_tempfile.write(secure_config_content)
        temp_cbor_filepath = named_tempfile.name

    return temp_cbor_filepath


def get_peer_mac(cfg: dict, peer_num: int = 0) -> str:
    pn = str(peer_num)
    try:
        premac = cfg['body']['scm2']['NET']['peers'][pn]['blue0']['mac'].strip()
    except:
        raise Exception("ERROR: Could not get peer MAC from config")
    try:
        validate_mac_address(premac)
        return premac
    except:
        formac = ':'.join(premac[i:i + 2] for i in range(0, len(premac), 2))
    return formac

# token = login("test.user1@fortrobotics.com", "1234")
# FRC
# config = get_device_config(token, "7xne5xjoyo")
# EPC
# config = get_device_config(token, "ipgqd6x5n6")
# mac = getPeerMac(config, 0)
# print(mac)
