import argparse
from boofuzz import *
from boofuzz import helpers
from boofuzz import constants
from base.bgp_update import BaseUpdateFuzzer

from boofuzz import Block

import random

from utils.fuzz_utils import bgp_fuzz_utils_class as my_fuzz_utils
import yaml

"""
BGP FLowspec fuzzing test case. This test case is designed to fuzz the flowspec NLRI 
in the MP_REACH_NLRI path attribute of a BGP UPDATE message. 

"""
class BgpUpdateFuzzer_Flowspec(BaseUpdateFuzzer):
    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        self.poc_name = 'BgpUpdateFuzzer_Flow2_testcase_%s.py'



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
            s_static(value=b"\x32", name="Opt Params Length")  # Optional Params Length
            s_static(value=b"\x02\x06\x01\x04\x00\x01\x00\x01", name="Afi-1 Safi=1")
            s_static(value=b"\x02\x06\x01\x04\x00\x01\x00\x85", name="Afi-1 Safi=133 flowspec")
            s_static(value=b"\x02\x02\x80\x00", name="route refresh cisco")
            s_static(value=b"\x02\x02\x02\x00", name="route refresh")
            s_static(value=b"\x02\x02\x46\x00", name="enhanced route refresh")
            s_static(value=b"\x02\x02\x06\x00", name="bgp extended message")
            s_static(value=b"\x02\x0a\x45\x08\x00\x01\x01\x01\x00\x01\x85\x01", name="add paths")
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

                        bgp_fuzz_utils._one_byte_fuzz("Origin Flags", random_options=False)
                        bgp_fuzz_utils._one_byte_fuzz("Origin Type Code", random_options=False)
                        bgp_fuzz_utils._one_byte_fuzz("Origin Length", random_options=False)
                        bgp_fuzz_utils._one_byte_fuzz("Origin IGP", random_options=False)
                        

                        bgp_fuzz_utils._one_byte_fuzz("AS Flags", random_options=False)
                        bgp_fuzz_utils._one_byte_fuzz("AS Type Code", random_options=False)
                        bgp_fuzz_utils._two_byte_fuzz("AS Length", random_options=False)


                        bgp_fuzz_utils._one_byte_fuzz("Local Flags", random_options=False)
                        bgp_fuzz_utils._one_byte_fuzz("Local Type Code", random_options=False)
                        bgp_fuzz_utils._one_byte_fuzz("Local Length", random_options=False)
                        bgp_fuzz_utils._four_byte_fuzz("Local Preference", random_options=False)



                        ## this is the rate limit values in an extended community
                        bgp_fuzz_utils._one_byte_fuzz("Extended Flags", random_options=False)
                        bgp_fuzz_utils._one_byte_fuzz("Extended Type", random_options=False)
                        bgp_fuzz_utils._one_byte_fuzz("Extended Length", random_options=False)

                        ## set the rate value
                        bgp_fuzz_utils._one_byte_fuzz("Carrier Extended Community", random_options=False)
                        bgp_fuzz_utils._one_byte_fuzz("Carrier Extended Community Subtype", random_options=False)
                        bgp_fuzz_utils._two_byte_fuzz("Carrier Extended Community AS", random_options=False)
                        bgp_fuzz_utils._four_byte_fuzz("Carrier Extended Rate", random_options=False)






                        with s_block("MP_REACH_NLRI"):
                            # mp reach flags is Optional non-transitive complete
                            bgp_fuzz_utils._one_byte_fuzz(name="Optional, Non-transitive, complete", random_options=False)
                            bgp_fuzz_utils._one_byte_fuzz(name="Type code MP_REACH_NLRI", random_options=False)
                            s_size(block_name="MP_REACH_NLRI", offset=-3, length=1, endian="big", fuzzable=False, name="MP_REACH_NLRI Length")
                            bgp_fuzz_utils._two_byte_fuzz(name="AFI IPv4", random_options=False)
                            bgp_fuzz_utils._one_byte_fuzz(name="SAFI Labeled Unicast", random_options=False)
                            bgp_fuzz_utils._one_byte_fuzz(name="Next Hop", random_options=False)
                            bgp_fuzz_utils._one_byte_fuzz(name="SNPA", random_options=False)

                            with s_block("FLOW_SPEC_NLRI"):

                                s_size(block_name="FLOW_SPEC_NLRI", offset=-1, length=1, endian="big", fuzzable=False, name="FLOW_SPEC_NLRI Length")

                                bgp_fuzz_utils._one_byte_fuzz(name="Destination prefix filter", random_options=False)
                                bgp_fuzz_utils._one_byte_fuzz(name="Destination prefix filter mask", random_options=False)
                                bgp_fuzz_utils._three_byte_fuzz(name="Destination prefix filter prefix", random_options=False)


                                bgp_fuzz_utils._one_byte_fuzz(name="Protocal / next header filter", random_options=False)
                                bgp_fuzz_utils._one_byte_fuzz(name="Operator flags", random_options=False)
                                bgp_fuzz_utils._one_byte_fuzz(name="Protocal value", random_options=False)

                                bgp_fuzz_utils._one_byte_fuzz(name="Source prefix filter", random_options=False)
                                bgp_fuzz_utils._one_byte_fuzz(name="Source prefix filter mask", random_options=False)
                                bgp_fuzz_utils._three_byte_fuzz(name="Source prefix filter prefix", random_options=False)


                                bgp_fuzz_utils._one_byte_fuzz(name="Destination Port Filter", random_options=False)
                                bgp_fuzz_utils._one_byte_fuzz(name="Destination Port Operator flags", random_options=False)
                                bgp_fuzz_utils._two_byte_fuzz(name="Destination Port", random_options=False)

                                bgp_fuzz_utils._one_byte_fuzz(name="Source Port Filter", random_options=False)
                                bgp_fuzz_utils._one_byte_fuzz(name="Source Port Operator flags", random_options=False)
                                bgp_fuzz_utils._two_byte_fuzz(name="Source Port", random_options=False)


                                bgp_fuzz_utils._one_byte_fuzz(name="TCP Flags Filter", random_options=False)
                                bgp_fuzz_utils._one_byte_fuzz(name="TCP Flags Filter Operator", random_options=False)
                                bgp_fuzz_utils._one_byte_fuzz(name="TCP Flags", random_options=False)


 



        self.session_handle.connect(s_get('BGP_OPEN'))
        self.session_handle.connect(s_get('BGP_OPEN'), s_get('BGP_KEEPALIVE'))
        self.session_handle.connect(s_get('BGP_KEEPALIVE'), s_get('BGP_UPDATE'))
        self.session_handle.fuzz()





if __name__ == '__main__':
    """
    Set the parameters
    """
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--fbgp_id', dest='fbgp_id', type=str, required=True, help='Fuzzer BGP ID.')
    argparser.add_argument('--fasn', dest='fasn', type=int, required=True, default=2, help='Fuzzer ASN number.')
    argparser.add_argument('--tip', dest='tip', type=str, required=True, help='Target IP address.')
    argparser.add_argument('--trpc_port', dest='trpc_port', type=int, required=True, default=1234, help='Target RPC port.')
    argparser.add_argument('--fuzzprofile', dest='fuzzprofile', type=str, required=True, help='File containing the fuzzing data.')
    argparser.add_argument('--configfile', dest='configfile', type=str, required=False, help='Configuration file to specify which fields to fuzz' \
    'values for fields. This is used to ensure that the packets are well formed, but can be overridden by the fuzzing \
    matrix to allow for fuzzing of specific fields. The config file should be a yaml file with a top level key of "default_values"')
    args = argparser.parse_args()

    FBGP_ID = args.fbgp_id
    FASN = args.fasn
    TIP = args.tip
    TRPC_PORT = args.trpc_port


    cfg_file = "bgp_defaults.yaml"
    if args.configfile:
        cfg_file = args.configfile

    config_matrix = yaml.safe_load(open(cfg_file))
    print("CONFIG MATRIX")
    print(yaml.dump(config_matrix))

    
    fuzz_matrix = None
    if args.fuzzprofile:
        print("Loading fuzzing matrix from file: %s" % args.fuzzprofile)
        FUZZ_FILE = args.fuzzprofile
        load_matrix = yaml.safe_load(open(FUZZ_FILE))
        fuzz_matrix = load_matrix["fuzzable"]

        print(yaml.dump(fuzz_matrix))

    """ create an instance of the fuzzing utility class with the config matrix and fuzzing matrix.
      The config matrix is used to provide default values for fields, while the fuzzing"""
    bgp_fuzz_utils = my_fuzz_utils(config_matrix=config_matrix, fuzz_matrix=fuzz_matrix)

    """
    Instantiate and run a test suite
    """
  
    fuzzer = BgpUpdateFuzzer_Flowspec(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    fuzzer.do_fuzz()
