from crypto import *
from utils import *


class Header:
    def __init__(self, dcid, q_version=1):
        self.q_version = q_version
        
        self.form = 1
        self.fixed_bit = 1
        self.reserved_bits = 0
        self.packet_number_length = 3
        self.dcid_len = 8
        self.dcid = dcid
        self.scid_len = 0
        self.scid = 0
        self.token_len = 0
        self.token = 0
        self.length = 1182
        self.packet_number = 0

        match self.q_version:
            case 1:
                self.long_packet_type = 0
                self.version = 1
                self.i_s = hkdf_extract(quic_salt, self.dcid.to_bytes(self.dcid_len, 'big'))
                self.client_initial_secret = hkdf_expand_label(self.i_s, client_in, 32)
                self.server_initial_secret = hkdf_expand_label(self.i_s, server_in, 32)
                self.key = hkdf_expand_label(self.client_initial_secret, quic_key, 16)
                self.iv = hkdf_expand_label(self.client_initial_secret, quic_iv, 12)
                self.hp = hkdf_expand_label(self.client_initial_secret, quic_hp, 16)
                self.nonce = byte_xor(self.iv, self.packet_number.to_bytes(12, "big"))
                self.s_key = hkdf_expand_label(self.server_initial_secret, quic_key, 16)
                self.s_iv = hkdf_expand_label(self.server_initial_secret, quic_iv, 12)
                self.s_hp = hkdf_expand_label(self.server_initial_secret, quic_hp, 16)
            case 2:
                self.long_packet_type = 1
                self.version = 0x6b3343cf
                self.i_s = hkdf_extract(quic_salt_v2, self.dcid.to_bytes(self.dcid_len, 'big'))
                self.client_initial_secret = hkdf_expand_label(self.i_s, client_in, 32)
                self.server_initial_secret = hkdf_expand_label(self.i_s, server_in, 32)
                self.key = hkdf_expand_label(self.client_initial_secret, quic_key_v2, 16)
                self.iv = hkdf_expand_label(self.client_initial_secret, quic_iv_v2, 12)
                self.hp = hkdf_expand_label(self.client_initial_secret, quic_hp_v2, 16)
                self.nonce = byte_xor(self.iv, self.packet_number.to_bytes(12, "big"))
                self.s_key = hkdf_expand_label(self.server_initial_secret, quic_key_v2, 16)
                self.s_iv = hkdf_expand_label(self.server_initial_secret, quic_iv_v2, 12)
                self.s_hp = hkdf_expand_label(self.server_initial_secret, quic_hp_v2, 16)

    def to_bytes(self, sample):
        result = bytearray()

        mask = aes_ecb_encrypt(self.hp, sample)[0:5]
        mid = self.form << 7 | self.fixed_bit << 6 | self.long_packet_type << 4 | self.reserved_bits << 2 | self.packet_number_length
        result.append(mid ^ (mask[0] & 0x0f))

        version = self.version.to_bytes(4, 'big')
        for i in version:
            result.append(i)

        dcid_len = self.dcid_len.to_bytes(1, 'big')
        result.append(dcid_len[0])

        dcid = self.dcid.to_bytes(self.dcid_len, 'big')
        for i in dcid:
            result.append(i)

        scid_len = self.scid_len.to_bytes(1, 'big')
        result.append(scid_len[0])
        if self.scid_len != 0:
            scid = self.scid.to_bytes(self.scid_len, 'big')
            for i in scid:
                result.append(i)

        token_len = wrap_integer(self.token_len)
        for i in token_len:
            result.append(i)
        if self.token_len != 0:
            token = self.token.to_bytes(self.token_len, 'big')
            for i in token:
                result.append(i)

        length = wrap_integer(self.length)
        for i in length:
            result.append(i)

        packet_number = self.packet_number.to_bytes(
            self.packet_number_length + 1, 'big')
        packet_number = byte_xor(
            packet_number, mask[1:1+self.packet_number_length + 1])
        for i in packet_number:
            result.append(i)

        return bytes(result)

    def to_bytes_raw(self):
        result = bytearray()

        mid = self.form << 7 | self.fixed_bit << 6 | self.long_packet_type << 4 | self.reserved_bits << 2 | self.packet_number_length
        result.append(mid)

        version = self.version.to_bytes(4, 'big')
        for i in version:
            result.append(i)

        dcid_len = self.dcid_len.to_bytes(1, 'big')
        result.append(dcid_len[0])

        dcid = self.dcid.to_bytes(self.dcid_len, 'big')
        for i in dcid:
            result.append(i)

        scid_len = self.scid_len.to_bytes(1, 'big')
        result.append(scid_len[0])
        if self.scid_len != 0:
            scid = self.scid.to_bytes(self.scid_len, 'big')
            for i in scid:
                result.append(i)

        token_len = wrap_integer(self.token_len)
        for i in token_len:
            result.append(i)
        if self.token_len != 0:
            token = self.token.to_bytes(self.token_len, 'big')
            for i in token:
                result.append(i)

        length = wrap_integer(self.length)
        for i in length:
            result.append(i)

        packet_number = self.packet_number.to_bytes(
            self.packet_number_length + 1, 'big')
        for i in packet_number:
            result.append(i)

        return bytes(result)


def extract_from_packet(my_dcid, packet: bytes):
    first_byte = packet[0]
    header_type = first_byte >> 7
    if header_type == 0:
        return 'short header', -1, 'short header'
    packet_type = (first_byte >> 4) & 0x03
    quic_version = int.from_bytes(packet[1:5], 'big')
    if quic_version != 1:
        if quic_version == 0x6b3343cf:
            quic_version = 2
    current = 5
    dcid_len = packet[current]
    dcid_len_len = int(dcid_len >> 6)
    match dcid_len_len:
        case 0:
            dcid_len = dcid_len & 0x3f
            current += 1
        case 1:
            dcid_len = int.from_bytes(packet[current:current+2], 'big') & 0x3fff
            current += 2
        case 2:
            dcid_len = int.from_bytes(packet[current:current+4], 'big') & 0x3fffffff
            current += 4
        case 3:
            dcid_len = int.from_bytes(packet[current:current+8], 'big') & 0x3fffffffffffffff
            current += 8
    dcid = 0 if dcid_len == 0 else int.from_bytes(packet[current:current+dcid_len], 'big')
    if dcid != my_dcid:
        if dcid == 0 and dcid_len == 0:
            dcid = my_dcid
        # else:
        #     raise Exception(f'dcid mismatch, received {dcid:x} != {my_dcid:x}')
    current += dcid_len
    
    scid_len = packet[current]
    scid_len_len = int(scid_len >> 6)
    match scid_len_len:
        case 0:
            scid_len = scid_len & 0x3f
            current += 1
        case 1:
            scid_len = int.from_bytes(packet[current:current+2], 'big') & 0x3fff
            current += 2
        case 2:
            scid_len = int.from_bytes(packet[current:current+4], 'big') & 0x3fffffff
            current += 4
        case 3:
            scid_len = int.from_bytes(packet[current:current+8], 'big') & 0x3fffffffffffffff
            current += 8
    scid = 0 if scid_len == 0 else int.from_bytes(packet[current:current+scid_len], 'big')
    current += scid_len
    
    if (packet_type != 0 and quic_version == 1) or (packet_type != 1 and quic_version == 2):
        # return scid, 'Handshake', f'not initial packet {quic_version} {packet_type}'
        return scid, 'Handshake', ''
    if quic_version != 1 and quic_version != 2:
        return scid, -1, f'unsupported version {quic_version:x}'
    
    header = Header(dcid, quic_version)
    
    token_len = packet[current]
    token_len_len = int(token_len >> 6)
    match token_len_len:
        case 0:
            token_len = token_len & 0x3f
            current += 1
        case 1:
            token_len = int.from_bytes(packet[current:current+2], 'big') & 0x3fff
            current += 2
        case 2:
            token_len = int.from_bytes(packet[current:current+4], 'big') & 0x3fffffff
            current += 4
        case 3:
            token_len = int.from_bytes(packet[current:current+8], 'big') & 0x3fffffffffffffff
            current += 8
    token = packet[current:current+token_len]
    current += token_len
    
    if current >= len(packet):
        return scid, -1, 'unexpected end of packet'
    
    packet_len = packet[current]
    packet_len_len = int(packet_len >> 6)
    match packet_len_len:
        case 0:
            packet_len = packet_len & 0x3f
            current += 1
        case 1:
            packet_len = int.from_bytes(packet[current:current+2], 'big') & 0x3fff
            current += 2
        case 2:
            packet_len = int.from_bytes(packet[current:current+4], 'big') & 0x3fffffff
            current += 4
        case 3:
            packet_len = int.from_bytes(packet[current:current+8], 'big') & 0x3fffffffffffffff
            current += 8
    # print(current)
    
    sample = packet[current+4:current+20]
    # print(sample.hex())
    mask = aes_ecb_encrypt(header.s_hp, sample)[0:5]
    # print(header.s_hp.hex())
    # print(mask.hex())     
    
    first_byte = first_byte ^ (mask[0] & 0x0f)
    # print(f'{first_byte:x}')
    pn_len = (first_byte & 0x03) + 1
    # print(pn_len)
    
    pn = packet[current:current+pn_len]
    # print(pn.hex())
    pn = byte_xor(pn, mask[1:1+pn_len])
    pn = int.from_bytes(pn, 'big')
    
    if dcid != my_dcid:
        return scid, pn, f'dcid mismatch, received {dcid:x} != {my_dcid:x}'
    return scid, pn, ''



if __name__ == "__main__":
    # header = Header(0x8394c8f03e515708, 1)
    # print(header.server_initial_secret.hex())
    # print(header.s_key.hex())
    # print(header.s_iv.hex())
    # print(header.s_hp.hex())
    # print(header.to_bytes_raw().hex())
    # print(header.to_bytes(unhexlify('6c3aea620687c318e2de50fbc5191dbb')).hex())
    packet = unhexlify('dd6b3343cf000458873dad0040753f9f1dd0c283170c10b6435046ad46d656a2eed43a737f5a4dc75fa6bcfabdd5b2c6a1bfd25533383bb5c5778170c3b60ada7bde56e90a054f5b32833e742206170e5ed76882f6853408ed8fa5f708c15c18f149bd827c80c8bef87e839f3c3da92a712253f5da66affd99c0cb1fe150bbe26312b1')
    scid, pn = extract_from_packet(0x7c5e3d0f64e23321, packet)
    print(f'{scid:x}', pn)
    pass
