import argparse
from boofuzz import *
from boofuzz import helpers
from boofuzz import constants
from base.bgp_update import BaseUpdateFuzzer

## extending primitives
from boofuzz.primitives import Byte

import random



import ipaddress

def encode_nlri_prefix(prefix_str, prefix_only=False):
    """
    Encode a CIDR prefix into BGP NLRI format
    
    Args:
        prefix_str: String like "192.168.1.0/24"
    
    Returns:
        bytes: Encoded NLRI prefix
    """
    network = ipaddress.ip_network(prefix_str, strict=False)
    prefix_length = network.prefixlen
    
    # Calculate bytes needed
    bytes_needed = (prefix_length + 7) // 8
    
    # Get the network address as bytes
    addr_bytes = network.network_address.packed
    
    # Truncate to only needed bytes
    prefix_bytes = addr_bytes[:bytes_needed]
    
    if prefix_only:
        return prefix_bytes
    else:
        # Return length + prefix
        return bytes([prefix_length]) + prefix_bytes



class s_group_extended():
    """ group that expands a decimain min/max into bytes and returns and s_group
    of those byte values. This means we can control exactly what byte values are used
    for fuzzing, rather than relying on s_byte to generate all 256 possible values."""
    def __init__(self, min, max, name="s_byte_extended", fuzzable=True):

        values = [x for x in range(min, max+1)]
        values_bytes = []
        #values_bytes = bytes(values)
        for v in values:
            print(f"{v} type is {type(v)}")
            print(f"{v.to_bytes(1, byteorder='big')} type is {type(v.to_bytes(1, byteorder='big'))}")

            values_bytes.append(v.to_bytes(1, byteorder='big'))
            
        print(f"values {values}")

        return s_group(values=values_bytes, name=name)




'''
BGP UPDATE Valid1

- BGP header length is correct
- Withdrawn routes length is set to 0x0000
- fuzz single attribute (extended length of 2 octets)
- attribute length is correct
'''
class BgpUpdateFuzzer_Valid1(BaseUpdateFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpUpdateFuzzer_6_testcase_%s.py'

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')    
        with s_block('HEADER'):    
            s_static(name='marker', value=b'\xff'*16)     
            s_static(name='length', value=b'\x00\x6b')    
            s_static(name='type', value=b'\x01')    
        with s_block('OPEN_MSG'):    
            s_static(name='version', value=b'\x04')    
            s_word(name='my_as', value=PARAM_ASN_ID, endian=BIG_ENDIAN, fuzzable=False)    
            s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name="Hold Time", fuzzable=False)
            s_static(name='bgp_identifier', value=helpers.ip_str_to_bytes(PARAM_BGP_ID))    
            s_static(name='opt_params_len', value=b'\x4e')    
            s_static(name='opt_params', value=b'\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00' \
                                              b'\x02\x02\x46\x00\x02\x06\x41\x04\x00\x00\x00\x02\x02\x02\x06\x00' \
                                              b'\x02\x06\x45\x04\x00\x01\x01\x01\x02\x13\x49\x11\x0f\x73\x74\x61' \
                                              b'\x6e\x64\x61\x73\x68\x2d\x75\x62\x75\x6e\x74\x75\x00\x02\x04\x40' \
                                              b'\x02\xc0\x78\x02\x09\x47\x07\x00\x01\x01\x80\x00\x00\x00'                      
            )                                                                  
                                                                              
        s_initialize('BGP_KEEPALIVE')                                                                    
        with s_block('HEADER'):                                                                                 
            s_static(name='marker', value=b'\xff'*16)                                                           
            s_static(name='length', value=b'\x00\x13')                        
            s_static(name='type', value=b'\x04')     
                                                                                                     
                                                     
        s_initialize('BGP_UPDATE')                                                                    
        with s_block('HEADER'):                                      
           s_static(name='marker', value=b'\xff'*16)                  
           s_size(name='header_len', length=2, math=lambda x: x + 19, block_name='UPDATE', endian=BIG_ENDIAN, fuzzable=False)
           s_static(name='type', value=b'\x02')                                                                                                                                                  

           with s_block('UPDATE'):
               s_word(name='withdrawn_len', value=b'\x00\x00', endian=BIG_ENDIAN, fuzzable=False)          
               s_size(name='total_path_attr_len', length=2, block_name='ATTRS', endian=BIG_ENDIAN, fuzzable=False)
               with s_block('ATTRS'):
                    ## this works, you can specify allowed values
                    #s_group(name='flags', values=[b'\xf0', b'\xd0', b'\xb0', b'\x90', b'\x70', b'\x50', b'\x30', b'\x10'])
                    s_byte(value=LimitedByte(value=0xf0, allowed_values=[0xf0, 0xd0, 0xb0, 0x90, 0x70, 0x50, 0x30, 0x10]), name='type_code', fuzzable=True)
                    s_byte(name='type_code', value=0x00, fuzzable=True)
                    s_size(name='attr_len', length=2, block_name='FUZZLOAD', endian=BIG_ENDIAN, fuzzable=False)
                    with s_block('FUZZLOAD'):
                        s_random(num_mutations=1024, min_length=0, max_length=1024, fuzzable=True)

      
        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'),s_get('BGP_KEEPALIVE'))
        self.session_handle.connect(s_get('BGP_KEEPALIVE'),s_get('BGP_UPDATE'))
        self.session_handle.fuzz()




'''
BGP UPDATE Valid2

- BGP header length is correct
- withdrawn routes length is 0
- ... followed by Path Attributes
'''
class BgpUpdateFuzzer_Valid2(BaseUpdateFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpUpdateFuzzer_Valid2_testcase_%s.py'


    def s_simple_byte(self, name="blah", fuzz_values=None, value=None, fuzzable=True):
        if fuzz_values is not None:
            value = random.choice(fuzz_values)
            return s_byte(name=name, value=value, fuzzable=False)
        return s_byte(name=name, value=value, fuzzable=fuzzable)

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_size(block_name="BGP_OPEN", length=2, endian="big", fuzzable=False, name="Length")  # Length
            s_static(name='type', value=b'\x01')
        with s_block('OPEN_MSG'):
            s_static(value=b"\x04", name="Version")  # BGP Version
            s_word(name='my_as', value=PARAM_ASN_ID, endian=BIG_ENDIAN, fuzzable=False)
            s_static(value=b"\x00\xb4", name="Hold Time")  # Hold Time
            s_static(name='bgp_identifier', value=helpers.ip_str_to_bytes(PARAM_BGP_ID))
            s_static(value=b"\x06", name="Opt Params Length")  # Optional Params Length
            s_static(value=b"\x02\x04\x40\x02\x80\x78", name="Opt Params")

        s_initialize('BGP_KEEPALIVE')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_static(name='length', value=b'\x00\x13')
            s_static(name='type', value=b'\x04')

        s_initialize('BGP_UPDATE')
        with s_block("BGP_UPDATE"):
            s_static(value=b"\xff" * 16, name="Marker")  # Marker
            s_size(block_name="BGP_UPDATE", length=2, endian="big", fuzzable=False, name="Length")  # Length
            s_static(value=b"\x02", name="Type")  # Type (UPDATE)
            with s_block("BGP_UPDATE Body"):
                s_static(value=b"\x00\x00", name="Withdrawn Routes Length")  # Withdrawn Routes Length
                s_size(block_name="Path Attributes", length=2, endian="big", fuzzable=False,
                       name="Path Attributes Length")
                with s_block("Path Attributes"):
                    with s_block("Path Attribute 1"):
                        s_static(value=b"\x40\x01\x01\x00",  name="Origin IGP")  # Attribute Origin IGP
                        s_static(value=b"\x50\x02\x00\x00", name="AS Path")
                        s_static(value=b"\x40\x03\x04\x0a\x03\x01\x76", name="Next Hop")

                with s_block("NLRI"):
                    #s_byte(fuzz_values=[16,17,18,19,20,21,22,23,24], name="Prefix Length3")  # Prefix length (subnet mask)
                    self.s_simple_byte(name="prefix2", fuzz_values=[16,17,18,19,20,21,22,23,24], fuzzable=False)  # Prefix length (subnet mask)
                    #s_byte(value=24, fuzzable=False, name="Prefix Length 1")  # Prefix length, (subnet mask)
                    s_static(value=b"\x6f\x00\x00", name="Prefix 1")  # Address (111.0.0.0)

        with s_block("BGP_UPDATE 2"):
            s_static(value=b"\xff" * 16, name="Marker 2")  # Marker
            s_size(block_name="BGP_UPDATE 2", length=2, endian="big", fuzzable=False, name="Length")  # Length
            s_static(value=b"\x02", name="Type")  # Type (UPDATE)
            with s_block("BGP_UPDATE Body 2"):
                s_static(value=b"\x00\x00", name="Withdrawn Routes Length 2")  # Withdrawn Routes Length
                s_size(block_name="Path Attributes 2", length=2, endian="big", fuzzable=False,
                       name="Path Attributes Length 2")
                with s_block("Path Attributes 2"):
                    with s_block("Path Attribute 2"):
                        s_static(value=b"\x40\x01\x01\x00",  name="Origin IGP 2")  # Attribute Origin IGP
                        s_static(value=b"\x50\x02\x00\x00", name="AS Path 2")
                        s_static(value=b"\x40\x03\x04\x0a\x03\x01\x76", name="Next Hop 2")

                with s_block("NLRI 2"):
                    #self.s_simple_byte(name="prefix2", fuzz_values=[16,17,18,19,20,21,22,23,24], )  # Prefix length (subnet mask)
                    s_byte(value=24, name="Prefix Length 2")  # Prefix length, (subnet mask)
                    s_static(value=b"\x6f\x01\x00", name="Prefix 2")  # Address (111.0.0.0)


        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'), s_get('BGP_KEEPALIVE'))
        self.session_handle.connect(s_get('BGP_KEEPALIVE'), s_get('BGP_UPDATE'))
        self.session_handle.fuzz()




'''
BGP UPDATE Valid3

- BGP header length is correct
- withdrawn routes length is 0
- ... followed by Path Attributes
'''
class BgpUpdateFuzzer_Valid3(BaseUpdateFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpUpdateFuzzer_Valid3_testcase_%s.py'


    def s_simple_byte(self, name="blah", fuzz_values=None, value=None, fuzzable=True):
        if fuzz_values is not None:
            value = random.choice(fuzz_values)
            return s_byte(name=name, value=value, fuzzable=False)
        return s_byte(name=name, value=value, fuzzable=fuzzable)

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('BGP_OPEN')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_size(block_name="BGP_OPEN", length=2, endian="big", fuzzable=False, name="Length")  # Length
            s_static(name='type', value=b'\x01')
        with s_block('OPEN_MSG'):
            s_static(value=b"\x04", name="Version")  # BGP Version
            s_word(name='my_as', value=PARAM_ASN_ID, endian=BIG_ENDIAN, fuzzable=False)
            s_static(value=b"\x00\xb4", name="Hold Time")  # Hold Time
            s_static(name='bgp_identifier', value=helpers.ip_str_to_bytes(PARAM_BGP_ID))
            s_static(value=b"\x06", name="Opt Params Length")  # Optional Params Length
            s_static(value=b"\x02\x04\x40\x02\x80\x78", name="Opt Params")

        s_initialize('BGP_KEEPALIVE')
        with s_block('HEADER'):
            s_static(name='marker', value=b'\xff' * 16)
            s_static(name='length', value=b'\x00\x13')
            s_static(name='type', value=b'\x04')

        s_initialize('BGP_UPDATE')
        with s_block("BGP_UPDATE"):
            s_static(value=b"\xff" * 16, name="Marker")  # Marker
            s_size(block_name="BGP_UPDATE", length=2, endian="big", fuzzable=False, name="Length")  # Length
            s_static(value=b"\x02", name="Type")  # Type (UPDATE)
            with s_block("BGP_UPDATE Body"):
                s_static(value=b"\x00\x00", name="Withdrawn Routes Length")  # Withdrawn Routes Length
                s_size(block_name="Path Attributes", length=2, endian="big", fuzzable=False,
                       name="Path Attributes Length")
                with s_block("Path Attributes"):
                    with s_block("Path Attribute 1"):
                        s_static(value=b"\x40\x01\x01\x00",  name="Origin IGP")  # Attribute Origin IGP
                        s_static(value=b"\x50\x02\x00\x00", name="AS Path")
                        s_static(value=b"\x40\x03\x04\x0a\x03\x01\x76", name="Next Hop")

                with s_block("NLRI"):
                    # this works but is static
                    #self.s_simple_byte(name="prefix2", fuzz_values=[16,17,18,19,20,21,22,23,24], fuzzable=False)  # Prefix length (subnet mask)
                    
                    #s_group(values=[16,17,18,19,20,21,22,23,24,25,26,27,28,29], name="Prefix Length Group")
                    #s_group(values=[b"\x10",b"\x11",b"\x12",b"\x13",b"\x14",b"\x15",b"\x16",b"\x17",b"\x18",b"\x19",b"\x1a",b"\x1b",b"\x1c",b"\x1d"], name="Prefix Length Byte Group")
                    
                    s_group_extended(min=17, max=32, name="Prefix Length Extended", fuzzable=True)

                    
                    ## NOTE that depending on the mask value, BGP expects the networks
                    ## to be encoded differently. For example, a /8 prefix only needs
                    ## 1 byte of address data, while a /24 needs 3 bytes. If we wanted real
                    ## values, use the encode_nlri_prefix function. it doesn't implement fuzzing however... needs more love.
                    s_static(value=b"\x6f\x00\x00", name="Prefix 1")  # Address (111.0.0.0)
                    #s_static(value=encode_nlri_prefix("111.0.0.0/8",True), name="Prefix Encoded 1")


        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'), s_get('BGP_KEEPALIVE'))
        self.session_handle.connect(s_get('BGP_KEEPALIVE'), s_get('BGP_UPDATE'))
        self.session_handle.fuzz()


'''
Modify this code to choose different test suites and parameters.
'''
if __name__ == '__main__':
    '''
    Set the parameters
    '''
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--fbgp_id', dest='fbgp_id', type=str, required=True, help='Fuzzer BGP ID.')
    argparser.add_argument('--fasn', dest='fasn', type=int, required=True, default=2, help='Fuzzer ASN number.')
    argparser.add_argument('--tip', dest='tip', type=str, required=True, help='Target IP address.')
    argparser.add_argument('--trpc_port', dest='trpc_port', type=int, required=True, default=1234, help='Target RPC port.')
    args = argparser.parse_args()

    FBGP_ID = args.fbgp_id
    FASN = args.fasn
    TIP = args.tip
    TRPC_PORT = args.trpc_port

    '''
    Instantiate and run a test suite
    '''
    fuzzer = BgpUpdateFuzzer_Valid3(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    fuzzer.do_fuzz()
