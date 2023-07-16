import socket
import ssl
import logging
import argparse
from hashlib import md5
from datetime import datetime

CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'

TLS_VERSION = {
    '0300': 'SSL 3.0',
    '0301': 'TLS 1.0',
    '0302': 'TLS 1.1',
    '0303': 'TLS 1.2',
    '0304': 'TLS 1.3',
}

EXTENSION_TYPE = {
    0: 'server_name',
    1: 'max_fragment_length',
    2: 'client_certificate_url',
    3: 'trusted_ca_keys',
    4: 'truncated_hmac',
    5: 'status_request',
    6: 'user_mapping',
    7: 'client_authz',
    8: 'server_authz',
    9: 'cert_type',
    10: 'supported_groups',
    11: 'ec_point_formats',
    12: 'srp',
    13: 'signature_algorithms',
    14: 'use_srtp',
    15: 'heartbeat',
    16: 'application_layer_protocol_negotiation',
    17: 'status_request_v2',
    18: 'signed_certificate_timestamp',
    19: 'client_certificate_type',
    20: 'server_certificate_type',
    21: 'padding',
    22: 'encrypt_then_mac',
    23: 'extended_master_secret',
    24: 'token_binding',
    25: 'cached_info',
    26: 'tls_lts',
    27: 'compress_certificate',
    28: 'record_size_limit',
    29: 'pwd_protect',
    30: 'pwd_clear',
    31: 'password_salt',
    32: 'ticket_pinning',
    33: 'tls_cert_with_extern_psk',
    34: 'delegated_credential',
    35: 'session_ticket',
    36: 'TLMSP',
    37: 'TLMSP_proxying',
    38: 'TLMSP_delegate',
    39: 'supported_ekt_ciphers',
    40: 'Reserved',
    41: 'pre_shared_key',
    42: 'early_data',
    43: 'supported_versions',
    44: 'cookie',
    45: 'psk_key_exchange_modes',
    46: 'Reserved',
    47: 'certificate_authorities',
    48: 'oid_filters',
    49: 'post_handshake_auth',
    50: 'signature_algorithms_cert',
    51: 'key_share',
    52: 'transparency_info',
    54: 'connection_id',
    55: 'external_id_hash',
    56: 'external_session_id',
    57: 'quic_transport_parameters',
    58: 'ticket_request',
    59: 'dnssec_chain',
    60: 'sequence_number_encryption_algorithms'
}


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--listen', help='specify listening address (example: 127.0.0.1:443)', default='127.0.0.1:443')
    parser.add_argument('-v', '--verbose', help='show log', action='store_true')
    args = parser.parse_args()
    try:
        listen_host, listen_port = args.listen.split(':')
        socket.inet_aton(listen_host)
        listen_port = int(listen_port)
        if not 1 <= listen_port <= 65535:
            raise Exception
        if args.verbose:
            logging.basicConfig(format='%(message)s', level=logging.DEBUG)
    except Exception as args_error:
        logging.error(args_error)
        print("Invalid listening address or port")
        exit()
    return listen_host, listen_port


def socket_listen(listen_host, listen_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((listen_host, listen_port))
        server_socket.listen(0)
        connect, address = server_socket.accept()
        return connect, address


def ssl_response(socket_conn, response_data):
    try:
        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        with ssl_context.wrap_socket(socket_conn, server_side=True, suppress_ragged_eofs=True) as ssl_socket:
            ssl_socket.do_handshake()
            response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(str(response_data))}\r\n\r\n{response_data}"
            ssl_socket.sendall(response.encode())
            ssl_socket.shutdown(socket.SHUT_RDWR)
    except ssl.SSLError as ssl_error:
        logging.warning(ssl_error)
        pass


def ja3(pack):
    cipher_suites_list, extension_list, supported_groups_list, ec_point_formats_list = ([] for i in range(4))
    tls_version_num = pack[9:11].hex()
    session_id_length = pack[43]
    cipher_suites_length = int.from_bytes(pack[44 + session_id_length:46 + session_id_length], 'big')
    cipher_suites_begin = 44 + session_id_length + 2
    for cipher_suite in range(cipher_suites_begin, cipher_suites_begin + cipher_suites_length, 2):
        cipher_suites_list.append(str(int.from_bytes(pack[cipher_suite:cipher_suite + 2], 'big')))
    compression_method_length = pack[cipher_suites_begin + cipher_suites_length]
    compression_method_begin = cipher_suites_begin + cipher_suites_length + 1
    extensions_length = int.from_bytes(pack[compression_method_begin +
                                            compression_method_length:compression_method_begin +
                                            compression_method_length + 2], 'big')
    logging.debug("Handshake Protocol:")
    logging.debug(" ├─ Handshake Type: %s ", pack[5])
    logging.debug(" ├─ Length: %s ", int.from_bytes(pack[6:9], 'big'))
    logging.debug(" ├─ Version: %s (0x%s)", TLS_VERSION[tls_version_num], tls_version_num)
    logging.debug(" ├─ Random: %s ", pack[11:43].hex())
    logging.debug(" ├─ Session ID Length: %s ", session_id_length)
    logging.debug(" ├─ Session ID: %s ", pack[44:44 + session_id_length].hex())
    logging.debug(" ├─ Cipher Suites Length: %s ", cipher_suites_length)
    logging.debug(" ├─ Cipher Suites: %s ", pack[cipher_suites_begin:cipher_suites_begin + cipher_suites_length].hex())
    logging.debug(" ├─ Compression Method Length: %s ", compression_method_length)
    logging.debug(" ├─ Compression Method: %s ", pack[compression_method_begin:compression_method_begin +
                                                      compression_method_length].hex())
    logging.debug(" ├─ Extentions Length: %s ", extensions_length)
    extensions_begin = extension_begin = compression_method_begin + compression_method_length + 2
    extension_length = 0
    while extension_begin + extension_length < extensions_begin + extensions_length:
        extension_type_num = int.from_bytes(pack[extension_begin:extension_begin + 2], 'big')
        extension_length = int.from_bytes(pack[extension_begin + 2:extension_begin + 4], 'big')
        if extension_type_num in EXTENSION_TYPE.keys():
            extension = EXTENSION_TYPE[extension_type_num]
        else:
            extension = 'unknown'
        logging.debug(" ├─ Extention: %s", extension)
        extension_list.append(str(extension_type_num))
        if extension_type_num == 10:
            supported_groups_list_length = int.from_bytes(pack[extension_begin + 4:extension_begin + 6], 'big')
            logging.debug(" │   ├─ Supported Groups List Length: %s", supported_groups_list_length)
            logging.debug(" │   ├─ Supported Groups: %s",
                          pack[extension_begin + 6:extension_begin + 6 + supported_groups_list_length].hex())
            for supported_group in range(extension_begin + 6, extension_begin + 6 + supported_groups_list_length, 2):
                supported_groups_list.append(str(int.from_bytes(pack[supported_group:supported_group + 2], 'big')))
        if extension_type_num == 11:
            ec_point_formats_length = pack[extension_begin + 4]
            logging.debug(" │   ├─ EC point formats Length: %s", ec_point_formats_length)
            logging.debug(" │   ├─ Elliptic curves point formats")
            for ec_point_format in range(extension_begin + 5, extension_begin + 5 + ec_point_formats_length):
                ec_point_formats_list.append(str(pack[ec_point_format]))
        logging.debug(" │   └─ Length: %s", extension_length)
        extension_begin += extension_length + 4
    ja3_full_string = ','.join([str(int(tls_version_num, 16)), '-'.join(cipher_suites_list), '-'.join(extension_list),
                               '-'.join(supported_groups_list), '-'.join(ec_point_formats_list)])
    logging.debug(" └─ JA3 Full string: %s", ja3_full_string)
    ja3_fingerprint = md5(ja3_full_string.encode()).hexdigest()
    return ja3_fingerprint


if __name__ == '__main__':
    host, port = get_arguments()
    while True:
        try:
            conn, addr = socket_listen(host, port)
            with conn:
                data = conn.recv(1024, socket.MSG_PEEK)
                if data and data[0] == 22:
                    time_now = datetime.now()
                    content = {"time": time_now.strftime("%Y/%m/%d-%H:%M:%S"), "ip": addr[0], "port": addr[1]}
                    content.update({"ja3": ja3(data)})
                    print(content)
                    ssl_response(conn, content)
                else:
                    continue
        except KeyboardInterrupt as e:
            print("\nUser exit.")
            break
        except Exception as e:
            logging.error(e)
            if "Address already in use" in str(e) or "Permission denied" in str(e):
                break
            else:
                continue
