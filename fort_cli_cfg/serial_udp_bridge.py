import linuxfd
import select
import socket
from threading import Thread
from typing import Tuple, Optional

import sliplib
from serial import Serial, SerialException
from sliplib import SlipStream

Addr = Tuple[str, int]


class SerialUdpBridge:
    """ Base class implementation of a Serial-UDP Bridge, where serial messages are SLIP-encoded.

    Child classes only need to override the  _route_udp_recv_callback() and _route_udp_destination_addr()
    """
    DEFAULT_ADDR = ('127.0.0.1', 56789)

    def __init__(self, *, serial: Serial, socket_addr: Addr = DEFAULT_ADDR):
        self._ser = serial
        self._ser.timeout = None
        self._slip = SlipStream(stream=self._ser, chunk_size=1)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # internet, UDP
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(socket_addr)

        self._slip_to_sock_thread: Thread = None
        self._sock_to_slip_thread: Thread = None

        self._slip_to_sock_killswitch = linuxfd.eventfd()
        self._sock_to_slip_killswitch = linuxfd.eventfd()

        self._running = False

    def _route_udp_recv_callback(self, data: bytes, addr: Addr) -> bool:
        """Override this in subclass. It will be called for every incoming udp data
        :param data the raw incoming data
        :param addr the source address
        :return True if this should be forwarded to the Serial"""
        raise NotImplementedError()

    def _route_udp_destination_addr(self, data: bytes) -> Optional[Addr]:
        """Override this in subclass. It will be called for every incoming serial slip message.
        :param data the raw message data
        :return the destination address to forward this packet to, or None to not forward it it"""
        raise NotImplementedError()

    @property
    def socket_addr(self) -> Tuple[str, int]:
        """get the addr (host:str, port:int) that this is actually bound to"""
        return self._sock.getsockname()

    def __del__(self):
        """try to clean up after deletion. attempt to close the socket"""
        self.stop()
        self._slip_to_sock_killswitch.close()
        self._sock_to_slip_killswitch.close()

    def _slip_to_sock(self):
        """thread that directs incoming slip messages from serial to current client address"""
        read_fds = [self._slip_to_sock_killswitch.fileno(), self._ser.fileno()]

        while True:
            read_ready_fds, _, _ = select.select(read_fds, [], [])
            if self._slip_to_sock_killswitch.fileno() in read_ready_fds:
                break

            if self._ser.fileno() in read_ready_fds:
                try:
                    data = self._slip.recv_msg()
                except sliplib.slip.ProtocolError as err:
                    print(f"exception occured in sliplib err({err})")
                    continue
                except SerialException:
                    return

                dest_addr = self._route_udp_destination_addr(data)

                if dest_addr:
                    try:
                        self._sock.sendto(data, dest_addr)
                    except Exception as e:
                        self._client_addr = None
                        print(f"client send exception({e})")

    def _sock_to_slip(self):
        """thread that directs incoming udp socket messages into slip messages to serial"""
        # self._slip.send_msg(b'')
        read_fds = [self._sock_to_slip_killswitch.fileno(), self._sock.fileno()]

        while True:
            read_ready_fds, _, _ = select.select(read_fds, [], [])
            if self._sock_to_slip_killswitch.fileno() in read_ready_fds:
                break

            if self._sock.fileno() in read_fds:
                data, addr = self._sock.recvfrom(1024)
                if len(data) == 0:
                    break
                if self._route_udp_recv_callback(data, addr):  # returns True if it should route to serial
                    self._slip.send_msg(data)

    def start(self):
        if not self._running:
            self._slip_to_sock_thread = Thread(target=self._slip_to_sock)
            self._sock_to_slip_thread = Thread(target=self._sock_to_slip)

            self._slip_to_sock_thread.start()
            self._sock_to_slip_thread.start()

            self._running = True

    def stop(self):
        if self._running:
            self._slip_to_sock_killswitch.write(1)
            self._slip_to_sock_thread.join()

            self._sock_to_slip_killswitch.write(1)
            self._sock_to_slip_thread.join()

            self._slip_to_sock_thread = None
            self._sock_to_slip_thread = None

            self._sock.close()
            self._running = False

    def __repr__(self) -> str:
        return "<{}: ({})---({}:{})>".format(self.__class__.__name__, self._ser.port, *self.socket_addr)


class SingleClientSerialUdpBridge(SerialUdpBridge):
    """Single-client implementation of the serial-udp bridge.
    All outgoing (from serial) traffic is routed to the UDP address of the last incoming message"""
    _current_client_addr: Addr = None

    def _route_udp_destination_addr(self, data: bytes) -> Optional[Addr]:
        # just returns the address of the last incoming message
        return self._current_client_addr

    def _route_udp_recv_callback(self, data: bytes, addr: Addr) -> bool:
        # incoming message, remember the address, and route everything to serial
        self._current_client_addr = addr
        return True


def main():
    """CLI interface to start up a SingleClientSerialUdpBridge to the specified serial port, and bind to the
    specified UDP port. """
    import argparse
    from serial.tools.list_ports import comports

    parser = argparse.ArgumentParser(description=main.__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('device', help='serial port device. Detected ports: {}'.format([p.device for p in comports()]))
    parser.add_argument('-b', '--baudrate', type=int, default=115200, help="serial port baud rate")
    parser.add_argument('-a', '--udpaddr', default=SingleClientSerialUdpBridge.DEFAULT_ADDR[0],
                        help='host to bind UDP socket')
    parser.add_argument('-p', '--udpport', type=int, default=SingleClientSerialUdpBridge.DEFAULT_ADDR[1],
                        help='port number to bind UDP socket')
    args = parser.parse_args()

    serial = Serial(args.device, baudrate=args.baudrate)
    socket_addr = (args.udpaddr, args.udpport)
    ss = SingleClientSerialUdpBridge(serial=serial, socket_addr=socket_addr)

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
