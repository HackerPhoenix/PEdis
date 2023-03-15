import pefile
from capstone import *

def main(path):
	global ActuallOffset, VirtualSize, VirtualAddress
	
	opcode_list = []
	pe = pefile.PE(path)

	print(pe.DOS_HEADER)
	print(pe.NT_HEADERS)
	print(pe.FILE_HEADER)
	print(pe.OPTIONAL_HEADER)
	
	ImageBase = pe.OPTIONAL_HEADER.ImageBase
	a=pe.OPTIONAL_HEADER.AddressOfEntryPoint
	for section in pe.sections:
		print(section)
	
	for section in pe.sections:
		print(section.Name)
		if section.Name == b'CODE\x00\x00\x00\x00':
#			print(181818181818181)
			VirtualAddress = section.VirtualAddress
			VirtualSize = section.Misc_VirtualSize
			ActuallOffset = section.PointerToRawData
#			print(ActuallOffset)
	StartVA = ImageBase + VirtualAddress
	StopVA = ImageBase + VirtualAddress + VirtualSize
	#print(hex(int(VirtualSize)))
	#print(hex(int(StopVA)))
	
	with open(path,"rb") as fp:
		fp.seek(ActuallOffset)
#		print(VirtualSize)
		HexCode = fp.read(VirtualSize)
		print(HexCode)
	md = Cs(CS_ARCH_X86, CS_MODE_32)
	for item in md.disasm(HexCode,0):
#		print(0)
		addr = hex(int(StartVA)+item.address)
		dic = {"Addr":str(addr), "OpCode":item.mnemonic+" " +item.op_str}
#		print("[+] 反汇编地址: {} 参数: {}".format(addr,dic))
		opcode_list.append(dic)
	
if __name__ == '__main__':
	path = "/home/hackii/Documents/PE/Acid burn.exe"
	main(path)
