import random
from boofuzz import *
from boofuzz import helpers
from boofuzz import constants
from base.bgp_update import BaseUpdateFuzzer


class bgp_fuzz_utils_class():

    def __init__(self, config_matrix=None, fuzz_matrix=None):
        """ initialize the fuzzing utility class with a config matrix and a fuzzing matrix.
        The config matrix is used to provide default values for fields, while the fuzzing
          matrix is used to determine which fields should be fuzzed. Both matrices are optional, 
          and if not provided, the class will default to using the fuzzable parameter for all fields.
          
          TODO add support for full range. This will fuzz every value not just the boundary values. THis is the "full_range" option.
          TODO add support for custom fuzzing functions for specific fields. This will allow for more targeted fuzzing of specific
            fields. This is the "full_values" option."""
        

        self.config_matrix = config_matrix
        self.fuzz_matrix = fuzz_matrix


    def __fuzz_item(self, field_name, fuzzable) -> bool:
        """ determine if a field should be fuzzed based on the fuzzing matrix. If the fuzzing matrix is not provided,
          default to the fuzzable parameter. If the field name is not in the fuzzing matrix, default to False. 
          Otherwise, return the value from the fuzzing matrix for that field name."""

        if self.fuzz_matrix is None:
            print("No fuzzing matrix provided, defaulting to fuzzable=%s for field %s" % (fuzzable, field_name))
            return fuzzable
        elif field_name not in self.fuzz_matrix:
            print("Field name %s not found in fuzzing matrix, defaulting to fuzzable=%s" % (field_name, fuzzable))
            return False
        else:
            print("Field name %s found in fuzzing matrix, setting to fuzzable=%s" % (field_name, self.fuzz_matrix[field_name]))
            return self.fuzz_matrix[field_name]



    def s_simple_byte(self, name="blah", fuzz_values=None, value=None, fuzzable=True):
        """ create a simple byte field with a default value of 0x10, but allow for fuzzing
          if the fuzz matrix is set to true for this field name. The default value can also
          """
        

        if fuzz_values is not None:
            value = random.choice(fuzz_values)
            return s_byte(name=name, value=value, fuzzable=False)
        return s_byte(name=name, value=value, fuzzable=fuzzable)


    def _one_byte_fuzz(self, name, random_options=False):
        """ create a 1 byte field with a default value of 0x10, but allow for fuzzing
          if the fuzz matrix is set to true for this field name."""
        
    
        if "default_values" in self.config_matrix and name in self.config_matrix["default_values"]:
            con_value = self.config_matrix['default_values'][name].replace(" ","")
            def_value = bytes.fromhex(con_value)
        else:
            def_value = b"\x10"
        if self.__fuzz_item(field_name=name, fuzzable=random_options):
            s_byte(value=def_value, name=name, fuzzable=True)
        else:
            s_static(value=def_value, name=name)
        
    def _two_byte_fuzz(self, name, random_options=False):
        """ create a 2 byte field with a default value of 0x10 repeated twice,
          but allow for fuzzing if the fuzz matrix is set to true for this field name. 
          The default value can also be overridden by the config matrix."""
        
        if "default_values" in self.config_matrix and name in self.config_matrix["default_values"]:
            con_value = self.config_matrix['default_values'][name].replace(" ","")
            def_value = bytes.fromhex(con_value)
        else:
            def_value = b"\x10\x10"
        if self.__fuzz_item(field_name=name, fuzzable=random_options):
            s_bytes(value=def_value, size=2, name=name, fuzzable=True)
        else:
            s_static(value=def_value, name=name)

    def _three_byte_fuzz(self, name, random_options=False):
        """ create a 3 byte field with a default value of 0x10 repeated 3 times, 
        but allow for fuzzing if the fuzz matrix is set to true for this field name."""

        if "default_values" in self.config_matrix and name in self.config_matrix["default_values"]:
            con_value = self.config_matrix['default_values'][name].replace(" ","")
            def_value = bytes.fromhex(con_value)
        else:
            def_value = b"\x10\x10\x10"
        if self.__fuzz_item(field_name=name, fuzzable=random_options):
            s_bytes(value=def_value, size=3, name=name, fuzzable=True)
        else:
            s_static(value=def_value, name=name)
        
    def _four_byte_fuzz(self, name, random_options=False):
        """ create a 4 byte field with a default value of 0x10 repeated 4 times,
          but allow for fuzzing if the fuzz matrix is set to true for this field name. 
          The default value can also be overridden by the config matrix."""
        
        if "default_values" in self.config_matrix and name in self.config_matrix["default_values"]:
            con_value = self.config_matrix['default_values'][name].replace(" ","")
            def_value = bytes.fromhex(con_value)
        else:
            def_value = b"\x10\x10\x10\x10"
        if self.__fuzz_item(field_name=name, fuzzable=random_options):
            s_bytes(value=def_value, size=4, name=name, fuzzable=True)
        else:
            s_static(value=def_value, name=name)

    def _eight_byte_fuzz(self, name, random_options=False):
        """ create an 8 byte field with a default value of 0x10 repeated 8 times, 
        but allow for fuzzing if the fuzz matrix is set to true for this field name. T
        he default value can also be overridden by the config matrix."""

        if "default_values" in self.config_matrix and name in self.config_matrix["default_values"]:
            con_value = self.config_matrix['default_values'][name].replace(" ","")
            def_value = bytes.fromhex(con_value)
        else:
            def_value = b"\x10\x10\x10\x10\x10\x10\x10\x10"
        if self.__fuzz_item(field_name=name, fuzzable=random_options):
            s_bytes(value=def_value, size=8, name=name, fuzzable=True)
        else:
            s_static(value=def_value, name=name)

    def _flowspec_port_one_or_two_byte(self, name="port block", random_options=False):
        """ create a flowspec port block with either a one byte or two byte port value. The operator 
        is set accordingly. either 0x81 or 0x91 depending on whether the port is one or two bytes.
        
        TODO break out the operator into it' own function to fuzz
        TODO create a version that tests just expressions
        """


        mode = random.choice([1,2])

        if mode == 1:
            with s_block(name):
                ## ransomize the operator, 1byte/2byte, gt, lt, eq, etc
                if random_options:
                    s_byte(value=b"\x81", name="Operator 1 byte port random", fuzzable=True)
                else:
                    s_static(value=b"\x81", name="Operator 1 byte port")

                # should never get here right? since the port value is only one byte, the operator should always be 0x81, but we can fuzz it if we want to
                #s_byte(value=b"\x50", fuzzable=True, name="Decimal value for port")
        else:
            with s_block(name):
                                ## ransomize the operator, 1byte/2byte, gt, lt, eq, etc
                if random_options:
                    s_bytes(size=2, value=b"\x91\x91", name="Operator 2 byte port random", fuzzable=True)
                else:
                    s_static(value=b"\x91\x91", name="Operator 2 bte port")

                #_static(value=b"\x91", name="Operator 2 byte port")
                # shoudl not get here
                #s_bytes(size=2, value=b"\x50\x00", fuzzable=True, name="Decimal value for port 16 bits")
        return mode