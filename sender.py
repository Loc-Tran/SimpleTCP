import sys
import time
import socket
import random
import pickle
import os
import threading

UNSIGNED_32_BIT_INTEGER_MAX = 2**32
time_at_start = 0
timer = False
used_packets = {}
current_ack_num = 0

class Packet:
    def __init__(self, packet_type, seq_number, ack_number):
        self.type = packet_type
        self.seq_num = seq_number
        self.ack_num = ack_number
        self.data = ''
        
    def append_payload(self, string_data):
        self.data = string_data
    
    def __repr__(self):
        return "-- Packet - Type: {}, SN: {}, AN: {}, Data {}".format(self.type, self.seq_num, self.ack_num, self.data)

def PLD_Module(pdrop):
    return random.random() > pdrop
    
def time_from_socket_connect_to_now(time_at_start):
    return time.time() - time_at_start
    
def write_to_logfile(packet, action, logfile):
    global time_at_start 
    time_packet_sent = time_from_socket_connect_to_now(time_at_start)
    logfile.write("{} {} {} {} {} {}\n".format(action, time_packet_sent, packet.type,
    packet.seq_num, len(packet.data), packet.ack_num))
    
def send_packet(socket, packet, logfile, pdrop):
    if PLD_Module(pdrop):
        socket.send(pickle.dumps(packet))
    write_to_logfile(packet, "snd", logfile)
    
def receive_packet(socket, logfile):
    packet_received = socket.recv(4096)
    write_to_logfile(pickle.loads(packet_received), "rcv", logfile)
    return pickle.loads(packet_received)    

def create_payloads(outfile, MSS):
    result = []
    while True:
        payload = outfile.read(MSS)
        if payload:
            result.append(payload)
        else:
            break
    return result
    
def get_final_stats(logread):
    bytes_transferred = 0
    packets_dropped = 0
    retransmitted_segments = 0
    for line in logread:
        data = line.split()
        if data[0] == "snd":
            bytes_transferred += int(data[4])
        if data[0] == "drop":
            packets_dropped += 1
            retransmitted_segments += 1
    return bytes_transferred, packets_dropped, retransmitted_segments

def give_total_dup_acks(dup_acks):
    result = 0
    for i in dup_acks.keys():
        if dup_acks[i] == 1:
            continue
        else:
            result += dup_acks[i] - 1
    return result

def ack_timeout(socket, timeout, pdrop, log):
    global used_packets
    global timer
    global current_ack_num
    
    write_to_logfile(used_packets[current_ack_num], "drop", log)
    send_packet(socket, used_packets[current_ack_num], log, pdrop)
    timer = threading.Timer(timeout/1000, ack_timeout, [socket, timeout, pdrop, log])
    timer.start()      
               
def sender(argv):
    global used_packets
    global timer
    global current_ack_num
	
    receiver_host_ip = argv[1]
    receiver_port = int(argv[2])
    filetxt = argv[3]
    MWS = int(argv[4])
    MSS = int(argv[5])
    timeout = float(argv[6])
    pdrop = float(argv[7])
    seed = int(argv[8])
    
    random.seed(seed)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((receiver_host_ip, receiver_port))
    global time_at_start
    time_at_start = time.time()
    LastByteSent = 0
    LastByteAcked = 0
    with open("Sender_log.txt", "w") as log, open(filetxt, "r") as outfile:
        client_isn = int(UNSIGNED_32_BIT_INTEGER_MAX * random.random())
        SYN_packet = Packet('S', client_isn, 0)
        send_packet(s, SYN_packet, log, 0)
        
        SYN_ACK_packet = receive_packet(s, log)
        server_isn = SYN_ACK_packet.seq_num
        
        ACK_packet = Packet('A', SYN_ACK_packet.ack_num, server_isn + 1)
        send_packet(s, ACK_packet, log, 0)

        client_seq_num = client_isn + 1
        server_seq_num = server_isn + 1
        payloads = create_payloads(outfile, MSS)
        size_of_last_payload = 0
        data_packets = []

        for payload in payloads:
            client_seq_num += size_of_last_payload
            data_packet = Packet('D', client_seq_num, server_seq_num)
            data_packet.append_payload(payload)
            size_of_last_payload = len(payload)
            data_packets.append(data_packet)
            
        current_ack_num = client_isn + 1
        current_server_seq_num = server_isn + 1

        with open(filetxt, 'r') as outf:
            outfile_size = len(outf.read())
        
        ACKS_received = {}
        
        fast_retransmitted_packets = 0
        current_window_size = 0
        timer = threading.Timer(timeout/1000, ack_timeout, [s, timeout, pdrop, log])
        
        while LastByteAcked < outfile_size:
            if current_window_size == 0:
                if timer.isAlive():
                    timer.cancel()
                    timer = threading.Timer(timeout/1000, ack_timeout, [s, timeout, pdrop, log])
                for data_packet in data_packets:
                    if data_packet.seq_num in used_packets.keys():
                        continue
                    if LastByteSent + len(data_packet.data) - LastByteAcked > MWS:
                        break
                    used_packets[data_packet.seq_num] = data_packet    
                    current_window_size += len(data_packet.data)
                    send_packet(s, data_packet, log, pdrop)
                    LastByteSent += len(data_packet.data)
                if not timer.isAlive():
                    timer.start()
                 
            ACK_packet = receive_packet(s, log)
            if (ACK_packet.ack_num > current_ack_num):
                LastByteAcked += ACK_packet.ack_num - current_ack_num
                current_window_size -= ACK_packet.ack_num - current_ack_num
                ACKS_received[ACK_packet.ack_num] = 1
                current_ack_num = ACK_packet.ack_num
                timer.cancel()
                timer = threading.Timer(timeout/1000, ack_timeout, [s, timeout, pdrop, log])
                timer.start()
            else:
                if ACK_packet.ack_num not in ACKS_received.keys():
                    ACKS_received[ACK_packet.ack_num] = 1
                else:
                    ACKS_received[ACK_packet.ack_num] += 1
                if ACKS_received[ACK_packet.ack_num] % 3 == 0:
                    fast_retransmitted_packets += 1
                    send_packet(s, used_packets[ACK_packet.ack_num], log, pdrop)  
        
        if timer.isAlive():                  
            timer.cancel()
        FIN_packet = Packet('F', current_ack_num, server_seq_num)
        send_packet(s, FIN_packet, log, 0)
        FINACK_packet = receive_packet(s, log)
        FIN_packet = receive_packet(s, log)
        ACK_packet = Packet('FA', FINACK_packet.ack_num + 1, FINACK_packet.seq_num + 1)
        send_packet(s, ACK_packet, log, 0)
    
    with open("Sender_log.txt", "r") as logread:
        bytes_transferred, packets_dropped, retransmitted_segments = get_final_stats(logread)
    retransmitted_segments += fast_retransmitted_packets
    data_segments_transferred = len(payloads)
    num_ACKS_received = give_total_dup_acks(ACKS_received)
        
    with open("Sender_log.txt", "a") as logwrite:
        logwrite.write("Amount of Data Transferred: {}\n".format(bytes_transferred))
        logwrite.write("Number of Data Segments Sent: {}\n".format(data_segments_transferred))
        logwrite.write("Number of Packets Dropped: {}\n".format(packets_dropped))
        logwrite.write("Number of Retransmitted Segments: {}\n".format(retransmitted_segments))
        logwrite.write("Number of Duplicate Acknowledgements received: {}\n".format(num_ACKS_received)) 
                   
if __name__ == "__main__":
    sender(sys.argv)
