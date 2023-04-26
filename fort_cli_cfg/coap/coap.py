import asyncio
import binascii
import json
import math
import pathlib
import sys

if sys.version_info >= (3, 7):
    from contextlib import asynccontextmanager
else:
    from async_generator import asynccontextmanager
from enum import Enum
from functools import wraps
from typing import Callable, NamedTuple
import struct

import aiocoap as coap
import cbor2


class FileInfo(NamedTuple):
    start_addr: int
    length: int
    crc32: int

    @staticmethod
    def from_bytes(b) -> 'FileInfo':
        return FileInfo(*struct.unpack_from('<III', b))

    @staticmethod
    def from_file(file_path: pathlib.Path) -> 'FileInfo':
        with open(file_path, 'rb') as f:
            data = f.read()
            return FileInfo(0, len(data), binascii.crc32(data))

    def to_bytes(self) -> bytes:
        return struct.pack('<III', *self)


class ContentFormat(int, Enum):
    Max = -1
    TextPlain = 0
    XML = 41
    OctetStream = 42
    JSON = 50
    CBOR = 60


def may_block(f):
    """
    Wraps an async function, allowing it to be called as a blocking function.

    Adds an optional 'blocking' keyword argument
        blocking=True -> run the wrapped function in an asyncio event loop until complete
        blocking=False [default] -> call the wrapped function
    Adds an optional 'timeout' keyword argument
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        timeout = kwargs.pop('timeout', None)
        if kwargs.pop('blocking', False):
            return asyncio.get_event_loop().run_until_complete(
                asyncio.wait_for(
                    f(*args, **kwargs), timeout
                )
            )
        return f(*args, **kwargs)

    return wrapper


def make_uri_str(host, path: str, query: str):
    """
    :return: "coap://<host>/[<path>][?<query>]"
    """
    return f"coap://{host}/{path}{'?' if query else ''}{query or ''}"


class ClientException(Exception):
    pass


@asynccontextmanager
async def coap_context():
    """
       Wrapper function that automates aiocoap.Context construction and shutdown boilerplate

       Intended to be used in an `async with` block:
       ```py
       async with CoapContext as ctx:
           request = await ctx.request(...)
       ```
       """
    ctx = await coap.Context.create_client_context()
    try:
        yield ctx
    finally:
        await ctx.shutdown()


@may_block
async def get_response(host: str, path: str, *, query: str = None, handle_blockwise: bool = True, **kwargs):
    """
    Basic COAP GET request

    kwargs are passed through to the Message constructor

    :param host: COAP host
    :param path: COAP endpoint
    :param query: COAP request query [default: None]
    :param handle_blockwise: allow aiocoap to handle blockwise requests automatically [default: True]
    :return: response object if successful, otherwise raises ClientException
    """
    async with coap_context() as ctx:
        response = await asyncio.wait_for(ctx.request(
            coap.Message(code=coap.Code.GET, uri=make_uri_str(host, path, query), **kwargs),
            handle_blockwise=handle_blockwise
        ).response, kwargs.get('timeout', None))
    if not response or not response.code.is_successful():
        raise ClientException(
            f"GET {make_uri_str(host, path, query)} response error ({'timeout' if not response else response.code})"
        )

    return response


@may_block
async def get(host: str, path: str, *, query: str = None, handle_blockwise: bool = True, **kwargs):
    """
    Basic COAP GET request

    kwargs are passed through to the Message constructor

    :param host: COAP host
    :param path: COAP endpoint
    :param query: COAP request query [default: None]
    :param handle_blockwise: allow aiocoap to handle blockwise requests automatically [default: True]
    :return: response payload, parsed according to the content_format
    """

    # since this function is a coroutine in and of itself that may block, don't pass the blocking kwarg through to
    # get_response
    kwargs.pop('blocking', None)

    # don't decode bytes into string (useful for e.g. IsmAddr.parse which only takes bytes)
    leave_bytes = kwargs.pop('leave_bytes', False)

    response = await get_response(host, path, query=query, handle_blockwise=handle_blockwise, **kwargs)
    if response.opt.content_format == ContentFormat.OctetStream or leave_bytes:
        return response.payload
    elif response.opt.content_format == ContentFormat.JSON:
        return json.loads(response.payload)
    elif response.opt.content_format == ContentFormat.CBOR:
        try:
            return cbor2.loads(response.payload)
        except cbor2.CBORDecodeError as e:
            print(f'GET error: CBOR decode - {e} (payload: {response.payload})')
            return None
    elif response.opt.content_format == ContentFormat.TextPlain or not response.opt.content_format:
        return response.payload.decode()


@may_block
async def get_manual_blockwise(host: str, path: str, query: str = None, block_size: int = 64, **kwargs):
    """
    Manual blockwise handling of a COAP GET request
    """

    # since this function is a coroutine in and of itself that may block, don't pass the blocking kwarg through to
    # get_response
    kwargs.pop('blocking', None)

    block_number = 0
    more = True
    while more:
        response = await get_response(
            host, path, query=query,
            handle_blockwise=False,
            block2=coap.optiontypes.BlockOption.BlockwiseTuple(block_number, True, _request_block_size_exp(block_size)),
            **kwargs
        )

        if response.code != coap.Code.CONTENT:
            raise ClientException(f'Invalid response code ({response.code}) - payload: {response.payload}')

        yield response.payload

        more = response.opt.get_option(coap.OptionNumber.BLOCK2)[0].value.more
        block_number += 1


async def _get_file_metadata(host: str, path: str):
    return FileInfo.from_bytes(bytes(await get(host, path, query="computed", leave_bytes=True)))


async def _get_file_length(host: str, path: str):
    # NOTE: telling get to leave the response as bytes here because the FRC sets content type of this response to CBOR
    #       but the file length is not valid CBOR (always? sometimes?) so we just ignore that
    # see also: core.SingleRoEndpointWithFakeCBORType
    return int.from_bytes(await get(host, f'{path}/length', leave_bytes=True), 'little')


async def _get_file_crc32(host: str, path: str):
    # NOTE: same as above
    return int.from_bytes(await get(host, f'{path}/crc', leave_bytes=True), 'little')


@may_block
async def get_validated_blockwise(host: str, path: str, output_file: pathlib.Path,
                                  progress: Callable[[int, int], None] = None):
    file_length = await _get_file_length(host, path)
    if file_length == 0:
        raise ClientException(f'GET file {path}/length returned 0')
    file_crc32 = await _get_file_crc32(host, path)

    data = b''
    async for chunk in get_manual_blockwise(host, f'{path}/data'):
        await asyncio.sleep(0.1)
        data += chunk
        if progress is not None:
            progress(len(data), file_length)

    checksum = binascii.crc32(data)
    if checksum != file_crc32:
        raise ClientException(f'GET file {path} invalid CRC32 (expected {file_crc32}, got {checksum})')

    with open(output_file, 'wb') as f:
        f.write(data)

    print(f'Wrote data to {output_file}')


@may_block
async def post_validated_blockwise(host: str, path: str, input_file: pathlib.Path,
                                   progress: Callable[[int, int], None] = None):
    with open(input_file, 'rb') as f:
        data = f.read()

    checksum = binascii.crc32(data)

    await post_blockwise(host, f'{path}/data', data, progress=progress)

    file_length = await _get_file_length(host, path)

    if file_length != len(data):
        raise ClientException(
            f"POST file {path} error: lengths don't match (local: {len(data)}; uploaded: {file_length})"
        )

    file_crc32 = await _get_file_crc32(host, path)

    if file_crc32 != checksum:
        raise ClientException(
            f"POST file {path} error: checksums don't match (local: {checksum}; uploaded {file_crc32}"
        )

    print(f'File {input_file} transferred successfully')
    return True


@may_block
async def get_file(host: str, path: str, metadata_path: str, output_file: pathlib.Path, target_filename: str,
                   progress: Callable[[int, int], None] = None):

    if not await post_text(host, path, target_filename):
        print(f"Could not prepare target to download file {target_filename}")
        return False

    file_metadata = await _get_file_metadata(host, metadata_path)
    file_length = file_metadata.length
    file_crc32 = file_metadata.crc32

    if file_length == 0:
        print(f'File metadata for {target_filename} has a length of 0')
        return False

    data = b''
    async for chunk in get_manual_blockwise(host, path):
        data += chunk
        if progress is not None:
            progress(len(data), file_length)

    checksum = binascii.crc32(data)
    if checksum != file_crc32:
        raise ClientException(f'GET file {path} invalid CRC32 (expected {file_crc32}, got {checksum})')

    with open(output_file, 'wb') as f:
        f.write(data)

    print(f'Wrote data to {output_file}')


# TODO: these may not work exactly (specifically the generator stuff, but they're not needed for NXP-283)
def get_sync(*args, **kwargs):
    return get(*args, blocking=True, **kwargs)


def get_manual_blockwise_sync(*args, **kwargs):
    return get_manual_blockwise(*args, blocking=True, **kwargs)


def get_file_sync(*args, **kwargs):
    return get_file(*args, blocking=True, **kwargs)


@may_block
async def post(host: str, path: str, payload: bytes, *, query: str = None, handle_blockwise: bool = True, **kwargs):
    """
    Basic COAP POST request

    kwargs are passed through to the Message constructor

    :param host: COAP host
    :param path: COAP endpoint
    :param payload: COAP request payload
    :param query: COAP request query [default: None]
    :param handle_blockwise: allow aiocoap to handle blockwise requests automatically [default: True]
    :return: response object
    """
    async with coap_context() as ctx:
        response = await asyncio.wait_for(ctx.request(
            coap.Message(code=coap.Code.POST, uri=make_uri_str(host, path, query), payload=payload, **kwargs),
            handle_blockwise=handle_blockwise
        ).response, kwargs.get('timeout', None))
    if not response or not response.code.is_successful():
        raise ClientException(
            f"POST {make_uri_str(host, path, query)} "
            f"response error ({'timeout' if not response else response.code}), payload={response.payload}"
        )
    return response


@may_block
async def post_text(host: str, path: str, payload, *, query: str = None, timeout: float = 15, **kwargs):
    # since this function is a coroutine in and of itself that may block, don't pass the blocking kwarg through to
    # post
    kwargs.pop('blocking', None)

    if isinstance(payload, str):
        payload = payload.encode()
    return await post(
        host, path, payload, query=query, timeout=timeout,
        # allow overriding the content type if it's set in kwargs (basically just to allow a `bytes` payload if needed)
        content_format=kwargs.pop('content_format', ContentFormat.TextPlain),
        **kwargs
    )


@may_block
async def post_cbor(host: str, path: str, payload, *, query: str = None, timeout: float = 15, **kwargs):
    # since this function is a coroutine in and of itself that may block, don't pass the blocking kwarg through to
    # post
    kwargs.pop('blocking', None)

    return await post(
        host, path, cbor2.dumps(payload), query=query,
        timeout=timeout, content_format=ContentFormat.CBOR,
        **kwargs
    )


@may_block
async def post_json(host: str, path: str, payload, *, query: str = None, timeout: float = 15, **kwargs):
    # since this function is a coroutine in and of itself that may block, don't pass the blocking kwarg through to
    # post
    kwargs.pop('blocking', None)

    return await post(
        host, path, json.dumps(payload).encode(), query=query,
        timeout=timeout, content_format=ContentFormat.JSON,
        **kwargs
    )


@may_block
def post_content_format(
        host: str, path: str, content_format: ContentFormat, payload, *,
        query: str = None, timeout: float = 15, **kwargs
):
    # since this function is a coroutine in and of itself that may block, don't pass the blocking kwarg through to
    # post
    kwargs.pop('blocking', None)

    delegate = {
        ContentFormat.TextPlain: post_text,
        ContentFormat.OctetStream: post,
        ContentFormat.JSON: post_json,
        ContentFormat.CBOR: post_cbor,
    }

    func = delegate.get(content_format, None)
    if func is None:
        raise NotImplementedError(f'this tool does not yet support {content_format}')

    return func(host, path, payload, query=query, timeout=timeout, **kwargs)


def _request_block_size_exp(block_size: int):
    """
    Get the closest valid COAP block-size-exp <= specified block-size
    """
    e = math.floor(math.log(block_size, 2) - 4)
    if 0 <= e < 8:
        return e
    raise ValueError(f'Invalid block_size ({block_size}), must be 16-2048')


@may_block
async def post_blockwise(
        host: str, path: str, payload: bytes, *,
        query: str = None, block_size: int = 64, progress: Callable[[int, int], None] = None, **kwargs
):
    """
    Post big data using aiocoap's automatic blockwise handling

    :param host: COAP host
    :param path: COAP endpoint
    :param payload: COAP request payload
    :param query: COAP request query [default: None]
    :param block_size: COAP request block size [default: 64]
    :param progress: optional callback function that takes two numbers representing fraction of total progress
    """

    # since this function is a coroutine in and of itself that may block, don't pass the blocking kwarg through to
    # post
    kwargs.pop('blocking', None)

    class BytesWrapper(bytes):
        def __getitem__(self, item):
            if isinstance(item, slice) and progress is not None:
                progress(item.stop, len(self))
            return super().__getitem__(item)

    return await post(
        host, path, BytesWrapper(payload), query=query,
        block1=coap.optiontypes.BlockOption.BlockwiseTuple(
            0, False, _request_block_size_exp(block_size=block_size)
        ), **kwargs
    )


@may_block
async def post_file(host: str, path: str, metadata_path: str, input_file: pathlib.Path, target_filename: str,
                    progress: Callable[[int, int], None] = None):
    with open(input_file, 'rb') as f:
        data = f.read()

    checksum = binascii.crc32(data)

    if not await post_text(host, path, target_filename):
        print(f"Could not prepare target to upload file {target_filename}")
        return False

    file_info = FileInfo.from_file(input_file)
    if not await post(host, metadata_path, file_info.to_bytes()):
        print(f"Could not upload file info for {target_filename}")
        return False

    if not await post_blockwise(host, path, data, progress=progress):
        return False

    onboard_computed_metadata = await _get_file_metadata(host, metadata_path)
    file_length = onboard_computed_metadata.length
    file_crc32 = onboard_computed_metadata.crc32

    if file_length != len(data):
        print(f"POST file {path} error: lengths don't match (local: {len(data)}; uploaded: {file_length})")
        return False

    if file_crc32 != checksum:
        print(f"POST file {path} error: checksums don't match (local: {checksum}; uploaded {file_crc32}")
        return False

    print(f'File {input_file} transferred successfully')
    return True


@may_block
async def get_response_observe(host: str, path: str, *, query: str = None, handle_blockwise: bool = True, **kwargs):
    """
    Basic COAP GET request

    kwargs are passed through to the Message constructor

    :param host: COAP host
    :param path: COAP endpoint
    :param query: COAP request query [default: None]
    :param handle_blockwise: allow aiocoap to handle blockwise requests automatically [default: True]
    :return: response object if successful, otherwise raises ClientException
    """
    async with coap_context() as ctx:
        req_msg = coap.Message(code=coap.Code.GET, uri=make_uri_str(host, path, query), **kwargs)
        req_msg.opt.observe = 0
        observation_is_over = asyncio.Future()
        try:
            request = ctx.request(req_msg, handle_blockwise=handle_blockwise)
            request.observation.register_errback(observation_is_over.set_result)
            request.observation.register_callback(lambda data: incoming_observation(data))
            response_data = await request.response
            if response_data.code.is_successful():
                present(response_data)
            else:
                raise ClientException(
                    f"GET {make_uri_str(host, path,query)} "
                    f"response error ({'timeout' if not response_data else response_data.code}, "
                    f"payload = {response_data.payload})"
                )
            exit_reason = await observation_is_over
            print("Observation is over: %r" % (exit_reason,), file=sys.stderr)
        finally:
            if not request.response.done():
                request.response.cancel()
            if not request.observation.cancelled:
                request.observation.cancel()


def incoming_observation(response):
    sys.stdout.write('---' + '\n')
    if response.code.is_successful():
        present(response, file=sys.stderr)
    else:
        sys.stdout.flush()
        print(response.code, file=sys.stderr)
        if response.payload:
            present(response, file=sys.stderr)


def present(message, file=sys.stdout):
    """Write a message payload to the output"""
    if not message.payload:
        return

    file.buffer.write(message.payload)
    if file.isatty() and message.payload[-1:] != b'\n':
        file.write("\n")


# apply monkey patch for _deduplicate_message to allow send large file > 67 MB size through aiocoap
def _deduplicate_message_patch(self, message):
    """Return True if a message is a duplicate, and re-send the stored
    response if available.

    Duplicate is a message with the same Message ID (mid) and sender
    (remote), as message received within last EXCHANGE_LIFETIME seconds
    (usually 247 seconds)."""

    key = (message.remote, message.mid, message.token)
    if key in self._recent_messages:
        if message.mtype is coap.CON:
            if self._recent_messages[key] is not None:
                self.log.info('Duplicate CON received, sending old response again')
                # not going via send_message because that would strip the
                # mid and might do all other sorts of checks
                self._send_initially(self._recent_messages[key])
            else:
                self.log.info('Duplicate CON received, no response to send yet')
        else:
            self.log.info('Duplicate NON, ACK or RST received')
        return True
    else:
        self.log.debug('New unique message received')
        self.loop.call_later(coap.numbers.constants.EXCHANGE_LIFETIME,
                             coap.protocol.functools.partial(self._recent_messages.pop, key))
        self._recent_messages[key] = None
        return False


def _store_response_for_duplicates_patch(self, message):
    """If the message is the response can be used to satisfy a future
    duplicate message, store it."""

    key = (message.remote, message.mid, message.token)
    if key in self._recent_messages:
        self._recent_messages[key] = message


coap.protocol.MessageManager._deduplicate_message = _deduplicate_message_patch
coap.protocol.MessageManager._store_response_for_duplicates = _store_response_for_duplicates_patch


# TODO: add synchronous variants
