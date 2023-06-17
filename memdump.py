import os, sys, re, string

from enum import IntEnum
from base64 import b64decode, b64encode
#from malduck import xor, rc4, base64

# c2 buffer len & invalid c2 placeholder
RACCOON_C2_PLACEHOLDER = b" " * 64
RACCOON_C2_BUFF_LEN = len(RACCOON_C2_PLACEHOLDER)

# c2s array size & key size
RACCOON_C2S_LEN = 5
RACCOON_KEY_LEN = 32

class ERaccoonBuild(IntEnum):
    UNKNOWN_BUILD = -1,
    OLD_BUILD = 0,
    NEW_BUILD = 1

# extracts ascii and unicode strings from binary file
class RaccoonStringExtractor:
    ASCII_BYTE = string.printable.encode()

    c2_list = []
    rc4_key = str()
    xor_key = str()
    raccoon_build = ERaccoonBuild.UNKNOWN_BUILD
    to_return_for_logs = ()
    
    def __init__(self, binary_path) -> None:
        with open(binary_path, 'rb') as bin:
            self.buffer = bin.read()
        self.__process_strings()

    def __is_base64_encoded(self, data) -> bool:
        try:
            data = data.rstrip()
            return b64encode(b64decode(data)) == data
        except Exception:
            return False

    def __is_valid_key(self, key) -> bool:
        key_re = re.compile(rb"^[a-z0-9]{%d,}" % RACCOON_KEY_LEN)
        return re.match(key_re, key)
        

    def __process_strings(self) -> None:
        ascii_re = re.compile(rb"([%s]{%d,})" % (self.ASCII_BYTE, 4))

        self.c2_list = []
        ascii_strings = []

        for i, match in enumerate(ascii_re.finditer(self.buffer)):
            a_string = match[0]
            offset = match.start()
            string_entry = (a_string, offset)
            ascii_strings.append(string_entry)

            if len(a_string) == RACCOON_C2_BUFF_LEN and \
                a_string != RACCOON_C2_PLACEHOLDER and \
                    self.__is_base64_encoded(a_string) == True:

                self.raccoon_build = ERaccoonBuild.OLD_BUILD
                #print(f"[+] found possible encrypted c2 {a_string.rstrip()} at {hex(offset)}")
                self.c2_list.append(string_entry)
                
                to_return_detection_type = "POSS_ENCR_C2"
                to_return_offset = hex(offset)
                to_return_IOC = a_string.rstrip()
                
                self.to_return_for_logs = (to_return_detection_type, to_return_offset, to_return_IOC)

                if len(self.c2_list) == 1: # first c2 found
                    rc4_key, offset = ascii_strings[i-1]
                    # rc4 key should be 32-bytes long and contain only a-z 0-9 chars
                    if self.__is_valid_key(rc4_key):
                        self.rc4_key = rc4_key
                        #print(f"[+] found possible rc4 key {self.rc4_key} at {hex(offset)}")
                        to_return_detection_type = "POSS_RC4_KEY"
                        to_return_offset = hex(offset)
                        to_return_IOC = self.rc4_key
                        self.to_return_for_logs = (to_return_detection_type, to_return_offset, to_return_IOC)
                    else:
                        continue
                
                  
        # have we found any c2s yet?
        if len(self.c2_list) == 0:
            for a_string, offset in ascii_strings:
                if len(a_string) == RACCOON_KEY_LEN and self.__is_valid_key(a_string):
                    self.raccoon_build = ERaccoonBuild.NEW_BUILD
                    self.xor_key = a_string
                    #print(f"[+] found possible xor key {self.xor_key} at {hex(offset)}")
                    to_return_detection_type = "POSS_XOR_KEY"
                    to_return_offset = hex(offset)
                    to_return_IOC = self.xor_key
                    
                    self.to_return_for_logs = (to_return_detection_type, to_return_offset, to_return_IOC)
                    
                    # extract c2s for new builds
                    curr_offset = offset + 36
                    for _ in range(0, RACCOON_C2S_LEN):
                        enc_c2 = self.buffer[curr_offset : curr_offset + RACCOON_C2_BUFF_LEN]
                        
                        if enc_c2.find(0x20) != 0 and enc_c2 != RACCOON_C2_PLACEHOLDER: # check if c2 is empty
                            #print(f"[+] found possible encrypted c2 {enc_c2.rstrip()} at {hex(curr_offset)}")
                            to_return_detection_type = "POSS_ENCR_C2"
                            to_return_offset = hex(curr_offset)
                            to_return_IOC = enc_c2.rstrip()
                            
                            self.c2_list.append((enc_c2, curr_offset))
                             
                            self.to_return_for_logs = (to_return_detection_type, to_return_offset, to_return_IOC)

                        curr_offset += RACCOON_C2_BUFF_LEN + 8 # each c2 is padded by 8 bytes
                    return # don't process strings any further
        else:
            return

        print(f"[!] C2Cs not found, could be a new build of raccoon sample")

class RaccoonC2Decryptor:
    def __init__(self, sample_path: str) -> None:
        self.extractor = RaccoonStringExtractor(sample_path)
        
    def for_logging(self) -> tuple:
        return_log_value = self.extractor.to_return_for_logs
        print(return_log_value)
        return return_log_value
    
    def __is_valid_c2(self, c2):
        return re.match(
            rb"((https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)", c2
        )

    def decrypt(self) -> bool:
        raccoon_build = self.extractor.raccoon_build
        if raccoon_build == ERaccoonBuild.OLD_BUILD:
            return self.decrypt_method_1()
        elif raccoon_build == ERaccoonBuild.NEW_BUILD:
            return self.decrypt_method_2()
        else:
            return False # unknown raccoon build

    # def decrypt_method_1(self) -> None:
    #     for enc_c2, _ in self.extractor.c2_list:
    #         decrypted_c2 = rc4(
    #             self.extractor.rc4_key, 
    #             base64(enc_c2.rstrip())
    #         )

    #         if self.__is_valid_c2:
    #             print(f"[>] decrypted c2: {decrypted_c2}")
    #         else:
    #             print(f"[!] invalid c2: {decrypted_c2}")

    # def decrypt_method_2(self) -> None:
    #     for enc_c2, _ in self.extractor.c2_list:
    #         decrypted_c2 = xor(
    #             self.extractor.xor_key, 
    #             enc_c2.rstrip()
    #         )
            
    #         if self.__is_valid_c2:
    #             print(f"[>] decrypted c2: {decrypted_c2}")
    #         else:
    #             print(f"[!] invalid c2: {decrypted_c2}")
                
def main(sample_path):
    # parse arguments
    # if len(sys.argv) == 2:
    #     sample_path = os.path.abspath(sys.argv[1])
    # else:
    #     print(f"[!] usage: {os.path.basename(__file__)} <sample path>")
    #     return False

    try:
        return (RaccoonC2Decryptor(sample_path).for_logging())
    except Exception as ex:
        print(f"[!] exception: {ex}")
    
 

# if __name__ == '__main__':
#     main()