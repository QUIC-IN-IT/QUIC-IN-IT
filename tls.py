from binascii import unhexlify
from utils import sni_bytes


class TLS:
    def __init__(self, sni):
        self.header = unhexlify("0303cc5ff765fb9eed0e6adc7ef2a0bc6f690baf810454a6f9ca9632b85f995df54d0000061301130213030100")

        sni = sni_bytes(sni)
        extension_upper = unhexlify("002b0003020304fe0d00ba0000010001540020fab21c471985179cf0228c0ecf3c4bb4e751ae08a6cbf3b7be2cc8af01099f510090c584ad0f50483cd27f484edfb4246ef83a3a255dbadedcf4d29abec7947d5f0967a7ed2512c42115664c8aac7915d49761b4c741bc5eef20bd2457f973a2d818123cdb0e7192cffb314f4f249b09a3dc01bc4f7e3a6793eb34ec2007f6917cda0053cb3170e97c6aab79ed9f82df75f6a9a3e4b539c548206330961102ecf2250834f9a2bce799ea52bd3f78457a33420039005a200480010000050480600000040480f00000c29cf283194a7f67055dcfe852138000475204000000010f00090240670802406480ff73db0c0000000100000001daea1aea060480600000030245c0070480600000010480007530000a00080006001d00170018446900050003026833002d00020101")
        extension_lower = unhexlify("003300260024001d0020f5d512827ccbc2c1a894cba8d5d7e0bfe021c30d52dc52da685f35b0fae4d355001000050003026833001b0003020002000d00140012040308040401050308050501080606010201")
        extension_length = len(extension_upper + sni + extension_lower)

        self.extension = extension_length.to_bytes(2, 'big') + extension_upper + sni + extension_lower
        self.len = len(self.header) + len(self.extension)

    def add_extension(self, extension):
        pass

    def to_bytes(self):
        type_and_len = self.len + 0x01000000
        type_and_len = type_and_len.to_bytes(4, 'big')
        return type_and_len + self.header + self.extension


if __name__ == "__main__":
    tls = TLS("quic.nginx.org").to_bytes()
    print(tls.hex())
