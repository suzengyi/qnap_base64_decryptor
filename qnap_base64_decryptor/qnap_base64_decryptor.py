import argparse
import logging
import base64

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.CRITICAL+1,format=LOG_FORMAT)

def _decrypt(encrypt_bytes:bytes,key:int,wheel:str)->bytes:
    wheel_rear=wheel[16:]
    temp=((((key >> 32) >> 28) + key) & 0xF)+((key >> 32) >> 28)
    decrypt_len=len(encrypt_bytes)
    decrypt_bytes=bytearray()
    for b in encrypt_bytes:
        if temp > 15:
            temp = 0
        if temp <=7:
            decrypt_bytes.append(b^ord(wheel[temp]))
        else :
            decrypt_bytes.append(b^ord(wheel_rear[temp]))
        temp=temp+1
    return decrypt_bytes

def decrypt(encrypt_bytes:bytes,key:int,wheel:str)->str:
    if len(wheel)!=32:
        raise TypeError()
    return _decrypt(encrypt_bytes,key,wheel).decode()

if __name__=='__main__':
    parse = argparse.ArgumentParser(description='QNAP base64 string decryptor')
    parse.add_argument("encrypt_str",type=str,
                       help='QNAP encrypted base64 string.')
    parse.add_argument('-k','--key',type=int,default=-1,
                       help='Decrypt key.')
    parse.add_argument('-w','--wheel',type=str,default='cde31qaz00000000000000005tgb9ijn',
                       help='The cipher wheel which you can find in libuLinux_Util.so (XOR_Encrypt function use). Length must be 32.')
    args=parse.parse_args()
    logging.debug(f"传入参数：{args}")
    encrypt_bytes=base64.b64decode(args.encrypt_str)
    logging.debug(f"加密字节：{encrypt_bytes}")
    if len(args.wheel)!=32:
        msg="bad cipher wheel"
        logging.critical("加密轮长度错误：{args.wheel}")
        print(msg)
        exit(-1)
    if args.key<0:
        for i in range(1,9):
            print(f"Testing with key {i}: ")
            print(decrypt(encrypt_bytes,i,args.wheel))
    else:        
        print(decrypt(encrypt_bytes,args.key,args.wheel))
    exit()
