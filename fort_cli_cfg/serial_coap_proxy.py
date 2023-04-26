from typing import List, Dict, NamedTuple, Optional

import aiocoap
from aiocoap import Message

from fort_cli_cfg.serial_udp_bridge import SerialUdpBridge, Addr, Serial


class ConMidData(NamedTuple):
    """maps confirmable coap message id's to udp address"""
    mid: int
    addr: Addr


class UdpAddrData(NamedTuple):
    token: bytes
    observe: int
    addr: Addr


class SerialCoapProxy(SerialUdpBridge):
    DEFAULT_LOOPBACK = '127.0.0.1'

    def __init__(self, *, serial: Serial, socket_addr: Addr = SerialUdpBridge.DEFAULT_ADDR,
                 loopback_redirect: str = DEFAULT_LOOPBACK):
        super().__init__(serial=serial, socket_addr=socket_addr)
        self._udp_requests_by_token = {}  # type: Dict[bytes, UdpAddrData]
        self._con_mid_list = []  # type: List[ConMidData]
        self._loopback = loopback_redirect

    def _route_udp_destination_addr(self, data: bytes) -> Optional[Addr]:
        """given an outgoing udp data message, router should return the target destination address,
        or None to not send"""
        try:
            message = Message.decode(data)
        except Exception as err:
            print("aiocoap.Message.decode error({})".format(err))
            return None

        if message.mtype == aiocoap.ACK or message.mtype == aiocoap.RST:
            md = next((e for e in self._con_mid_list if e.mid == message.mid), None)
            if md:
                print("Got ({}) for obj({}) ({}):({})".format(message.mtype, md, message.code, aiocoap.Code.EMPTY))
                self._con_mid_list.remove(md)
                addr = md.addr
                if len(data) == 4:  # for empty message do not try to parse other information
                    return addr
            else:
                print("Type({}) Mid({}) not found in the list".format(message.mtype, message.mid))

        """
        If a request is received from serial port, then it should be routed on ip and port
        received in uri_host & uri_port option.
        If host option is not received then it should be routed to loopback ip i.e. 127.0.0.1
        If port option is not received then it should be routed to default port i.e. 5683
        """
        if message.code.is_request():
            if not message.opt.uri_host:
                print("host not found in frame with token({}), routing to loopback ip".format(message.token))
                host = "127.0.0.1"
            else:
                host = message.opt.uri_host

            if message.opt.uri_port is None or 0 == message.opt.uri_port:
                print("port not found in frame with token({}), routing to coap standard port".format(message.token))
                port = 5683
            else:
                port = message.opt.uri_port

            if host == self.DEFAULT_LOOPBACK:
                host = self._loopback

            print("Request Tkn({}) sending on ({})".format(message.token.hex(), (host, port)))
            return (host, port)

        """
        If a response is received from serial port, then it should be routed on ip and port
        for the Token matched entry found in our list.
        The entry shoould be removed in following cases:
        1.  If received response is a reject response.
        2.  If request doesn't contain observe option or the observe option has been set to cancel.
        """
        if message.token not in self._udp_requests_by_token:
            print("Item with token not found in list({}), discarding frame".format(message.token.hex()))
            return

        u = self._udp_requests_by_token[message.token]

        if message.code.is_successful() is not True or u.observe is None or 1 == u.observe:
            self._udp_requests_by_token.pop(message.token)
            print("Removed entry for ({}), Total({})".format(u, len(self._udp_requests_by_token)))

        return u.addr

    def _route_udp_recv_callback(self, data: bytes, addr: Addr) -> bool:
        try:
            message = Message.decode(data)
        except Exception as e:
            print("aiocoap.Message.decode error ({})".format(e))
            return False

        if message.mtype == aiocoap.CON:
            cm = ConMidData(message.mid, addr)
            self._con_mid_list.append(cm)
            print("Waiting for ACK for the response with tid({})".format(cm))

        # response, send directly to serial
        if message.code.is_response():
            print("Response Tkn({}) Code({}) rcvd from ({})".format(message.token.hex(), message.code, addr))
            return True

        """ Requests
        If request is received from UDP port, then we have to store the received from
        address(IP & Port), Token Value and Observe Option(if received). This will be used
        when the response is received for that Token to route the request.
        """
        ud = UdpAddrData(message.token, message.opt.observe, addr)
        if message.token in self._udp_requests_by_token:
            print("Item ({}) already found in list, updated values".format(ud))
        else:
            print("Added entry for ({}), Total({})".format(ud, len(self._udp_requests_by_token)))
        self._udp_requests_by_token[message.token] = ud

        return True


def main():
    """CLI interface to start up a SerialCoapProxy to the specified serial port, and bind to the specified UDP port.
    Example usages:

    - [FRC <--USB_OTG--> EPC]
      set EPC coap addr in /etc/fort_peermgr.cfg to "coap://127.0.0.1:56789

        serial-coap-proxy /dev/ttyACM0

    - [FRC <--USB--> PC <--ETHERNET--> EPC] EPC-IP=192.168.3.10. PC-IP=192.168.3.XX
      set EPC coap addr in /etc/fort_peermgr.cfg to "coap://192.168.3.XX:56789
      Bind addr to 0.0.0.0 to make available on network. Set loopback-forwarding to EPC-IP (192.168.3.10)

        serial-coap-proxy /dev/ttyACM0 -a 0.0.0.0 -l 192.168.3.10
    """
    import argparse
    from serial.tools.list_ports import comports

    class CustomArgParseFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
        pass

    parser = argparse.ArgumentParser(description=main.__doc__, formatter_class=CustomArgParseFormatter)
    parser.add_argument('device', help='serial port device. Detected ports: {}'.format([p.device for p in comports()]))
    parser.add_argument('-b', '--baudrate', type=int, default=115200, help="serial port baud rate")
    parser.add_argument('-a', '--udpaddr', default=SerialCoapProxy.DEFAULT_ADDR[0], help='host to bind UDP socket')
    parser.add_argument('-p', '--udpport', type=int, default=SerialCoapProxy.DEFAULT_ADDR[1],
                        help='port number to bind UDP socket')
    parser.add_argument('-l', '--loopback', type=str, default=SerialCoapProxy.DEFAULT_LOOPBACK,
                        help='host to redirect loopback addr to')
    args = parser.parse_args()

    port = args.device
    if port == 'auto':
        port = next(d.device for d in comports() if d.pid == 0xd101)

    serial = Serial(port, baudrate=args.baudrate)
    socket_addr = (args.udpaddr, args.udpport)
    ss = SerialCoapProxy(serial=serial, socket_addr=socket_addr, loopback_redirect=args.loopback)

    print(ss)
    ss.start()
    while 1:
        try:
            input('CTRL+C to exit\n')
        except KeyboardInterrupt:
            break
    print('exiting...')


if __name__ == "__main__":
    main()
