# pip install python-iptables
import socket
import select
import signal
import ctypes
import struct

import iptc
from libnetfilter.log import nflog_handle
from libnetfilter.netlink import nf_log

  
running = True
def signal_handler(signal, frame):
	global running
	running = False
signal.signal(signal.SIGINT, signal_handler)

def nfbpf_compile(pattern):
	from bpf import libpcap, bpf_program
	buf = ctypes.c_char_p(pattern)
	optimize = ctypes.c_int(1)
	mask = ctypes.c_int(0xffffffff)
	program = bpf_program()
	DLT_RAW = 12
	libpcap.pcap_compile_nopcap(40, DLT_RAW, ctypes.byref(program), buf, optimize, mask)
	if program.bf_len > 64: # XT_BPF_MAX_NUM_INSTR
		raise ValueError("bpf: number of instructions exceeds maximum")
	r = "{:d}, ".format(program.bf_len)
	r += ", ".join(["{i.code} {i.jt} {i.jf} {i.k}".format(i=program.bf_insns[i]) for i in range(program.bf_len)])
	print(r)
	return r


class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'

	@staticmethod
	def ok(data):
		return bcolors.OKGREEN + data + bcolors.ENDC
	@staticmethod
	def fail(data):
		return bcolors.FAIL + data + bcolors.ENDC
	@staticmethod
	def next(data):
		return bcolors.OKBLUE + data + bcolors.ENDC


def trace_cb(gh, nfmsg, nfa, data):
	prefix = nfa.prefix
	if not prefix.startswith('TRACE: '):
		return 0


	# chainname may have :, therefore split and re-create chainname
	p = prefix[7:].split(":")
	tablename,chainname,type,rulenum = [p[0], ':'.join(p[1:-2]), p[-2], p[-1]]

	table = iptc.Table(tablename)
	chain = iptc.Chain(table, chainname)
	pkt = nfa.payload
#	h3 = iphdr.from_buffer(pkt)
#	
#	if tablename == 'raw' and chainname in ('PREROUTING','OUTPUT'):
#		print("{} {} {} {} -> {}".format(h3.ip_hl, h3.version, h3.protocol, h3.src, h3.dst))
#		if h3.protocol == socket.IPPROTO_TCP:
#			h4 = tcphdr.from_buffer(pkt, h3.off)
#			print("tcp {} -> {}".format(h4.src, h4.dst))
#		elif h3.protocol == socket.IPPROTO_UDP:
#			h4 = udphdr.from_buffer(pkt, h3.off)
#			print("udp {} -> {}".format(h4.src, h4.dst))
#		elif h3.protocol == socket.IPPROTO_ICMP:
#			h4 = icmphdr.from_buffer(pkt, h3.off)
#			print("icmp {}:{}".format(h4.type, h4.code))
#		else:
#			return
	if tablename == 'raw' and chainname in ('PREROUTING','OUTPUT'):
		print(nf_log(pkt, nfa.indev, nfa.outdev))
	
	r = "\t{} {} ".format(tablename,chainname)
	if type == 'policy':
		x = chain.get_policy().name
		if x == 'ACCEPT':
			x = bcolors.ok(x)
		else:
			x = bcolors.fail(x)
	elif type == 'rule':
		r += "(#{r}) ".format(r=rulenum.strip())
		rule = chain.rules[int(rulenum)-1]
		x = "{r.protocol} {r.src} -> {r.dst} ".format(r=rule)
		for m in rule.matches:
			if m.name == 'comment':
				r += "/* {} */".format(m.get_all_parameters()['comment'])
			else:
				x += "{}:{} ".format(m.name,m.get_all_parameters().__str__())

		tp = rule.target.get_all_parameters()
		if len(tp) > 0:
			tp = str(tp)
		else:
			tp = ""

		if rule.target.name == 'ACCEPT':
			targetname = bcolors.ok(rule.target.name)
		elif rule.target.name in ('REJECT','DROP'):
			targetname = bcolors.fail(rule.target.name)
		else:
			targetname = bcolors.next(rule.target.name)
		x += "\n\t\t=> {} {}".format(targetname, tp)
	elif type == 'return':
		x = "return"

	print("{}\n\t\t{}".format(r,x))
	return 0


def main():
	global running
	import argparse
	import random

	parser = argparse.ArgumentParser(description='iptables-trace')
	
	parser.add_argument('--clear-chain', action='store_true', default=False, help="delete all rules in the chain")
	parser.add_argument('--chain','-c', type=str, nargs='*', choices=['OUTPUT','PREROUTING'], default=["OUTPUT",'PREROUTING'], help='chain')
	parser.add_argument('--source','-s', type=str, action='store', default=None, help='source')
	parser.add_argument('--destination','-d', type=str, action='store', default=None, help='destination')
	parser.add_argument('--protocol', '-p', type=str, action='store', default=None, help='protocol')	
	parser.add_argument('--bpf',type=str, default=None, action='store')
	parser.add_argument('--xmark-mask', '-M', type=str, action='store', default="0x800001ff", help='mark mask (bits to use) default is not to use lower 9 bits and the highest')
	parser.add_argument("--limit", action='store_true', default=False, help="limit rule matches to 1/second")
	
	args = parser.parse_args()
	print(args)

	if not iptc.is_table_available(iptc.Table.RAW):
		raise ValueError("table raw does not exist")
	table = iptc.Table("raw")

	rules = []
	for i in args.chain:
		chain = iptc.Chain(table, i)
		if args.clear_chain == True and len(chain.rules) != 0:
			while len(chain.rules) > 0:
				i = chain.rules[0]
				print("delete rule {}".format(i))
				chain.delete_rule(i)

		mark = iptc.Rule()
		if args.protocol:
			mark.protocol = args.protocol
		if args.source:
			mark.src = args.source
		if args.destination:
			mark.dst = args.destination

		if args.bpf:
			bpf = mark.create_match("bpf")
			bpf.bytecode = nfbpf_compile(args.bpf)
			comment = mark.create_match("comment")
			comment.comment = 'bpf: "{}"'.format(args.bpf)
		if args.limit:
			limit = mark.create_match('limit')
			limit.limit = "1/second"
			limit.limit_burst = "1"
		
		mark.target = iptc.Target(mark, "MARK")
		m = 0
		while m == 0:
			_m = random.randint(0,2**32-1)
			_m &= ~int(args.xmark_mask, 16)
			m = "0x{:x}".format(_m)
		mark.target.set_mark = m
		chain.append_rule(mark)
		rules.append((chain,mark))

		trace = iptc.Rule()
		match = trace.create_match("mark")
		match.mark = "{}/0x{:x}".format(m,0xffffffff & ~int(args.xmark_mask, 16))
		trace.target = iptc.Target(trace, "TRACE")
		chain.append_rule(trace)
		rules.append((chain,trace))

	n = nflog_handle.open()
	r = n.unbind_pf(socket.AF_INET)
	r = n.bind_pf(socket.AF_INET)
	qh = n.bind_group(0)
	qh.set_mode(0x02, 0xffff)

	qh.callback_register(trace_cb, None);

	fd = n.fd

	while running:
		try:
			r,w,x = select.select([fd],[],[],1.)
			if len(r) == 0:
				# timeout
#				print("timeout")
				continue
			if fd in r:
				n.handle_io()
		except:
			pass

	for chain,rule in rules:
		chain.delete_rule(rule)

if __name__ == '__main__':
	main()

