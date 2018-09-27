UNSIGNED_32_BIT_INTEGER_MAX = 2**32
time_at_start = 0

import sys
import time
import socket
import random
import pickle
import os
from sender import Packet

def time_from_socket_connect_to_now(time_at_start):
    return time.time() - time_at_start
    
def write_to_logfile(packet, action, logfile):
    global time_at_start 
    time_packet_sent = time_from_socket_connect_to_now(time_at_start)
    logfile.write("{} {} {} {} {} {}\n".format(action, time_packet_sent, packet.type,
    packet.seq_num, len(packet.data), packet.ack_num))
    
def send_packet(socket, address, packet, logfile):
    socket.sendto(pickle.dumps(packet), address)
    write_to_logfile(packet, "snd", logfile)
    
def receive_packet(socket, logfile):
    packet_received = socket.recv(4096)
    write_to_logfile(pickle.loads(packet_received), "rcv", logfile)
    return pickle.loads(packet_received)   

def get_final_stats(logread):
    bytes_recv = 0
    data_segments_recv = 0
    
    for line in logread:
        data = line.split()
        if data[0] == "rcv":    
            bytes_recv += int(data[4])
        if data[2] == "D":
            data_segments_recv += 1
    return bytes_recv, data_segments_recv

    
def write_to_outfile(data_packet, outfile):
    outfile.write(data_packet.data)
    
def receiver(argv):
    receiver_port = int(argv[1])
    filetxt = argv[2]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', receiver_port))
    
    client_address = False
    client_port = 0
    packet_buffer = {}
    client_isn = 0
    server_isn = int(UNSIGNED_32_BIT_INTEGER_MAX * random.random())
    
    first_udp_datagram = s.recvfrom(4096)
    global time_at_start
    time_at_start = time.time()
    received_packet = pickle.loads(first_udp_datagram[0])
    client_address = first_udp_datagram[1]
    client_isn = received_packet.seq_num
    duplicate_segs = 0
    
    with open("Receiver_log.txt", "w") as log, open(filetxt, "w") as outfile:
        if received_packet.type == 'S':
            expected_client_seq_num = client_isn + 1
            SYNACK_packet = Packet('SA', server_isn, expected_client_seq_num)
            send_packet(s, client_address, SYNACK_packet, log)
            ACK_packet = receive_packet(s, log)
            current_server_seq_num = ACK_packet.ack_num        
        while True:    
            received_packet = receive_packet(s, log)
            if received_packet.type == 'A':
                continue
            elif received_packet.type == 'D':
                if expected_client_seq_num == received_packet.seq_num:
                    expected_client_seq_num += len(received_packet.data)
                    ACK_packet = Packet('A', current_server_seq_num, expected_client_seq_num)
                    send_packet(s, client_address, ACK_packet, log)
                    write_to_outfile(received_packet, outfile)
                    while expected_client_seq_num in packet_buffer.keys():
                        packet_in_buffer_seq_num = expected_client_seq_num
                        write_to_outfile(packet_buffer[packet_in_buffer_seq_num], outfile)
                        expected_client_seq_num += len(packet_buffer[packet_in_buffer_seq_num].data)
                        ACK_packet = Packet('A', current_server_seq_num, expected_client_seq_num)
                        send_packet(s, client_address, ACK_packet, log)

                        del packet_buffer[packet_in_buffer_seq_num]
                elif expected_client_seq_num < received_packet.seq_num:
                    if received_packet.seq_num not in packet_buffer.keys():    
                        packet_buffer[received_packet.seq_num] = received_packet
                    ack_packet = Packet('A', current_server_seq_num, expected_client_seq_num)
                    send_packet(s, client_address, ack_packet, log)
                else:
                    ack_packet = Packet('A', current_server_seq_num, expected_client_seq_num)
                    send_packet(s, client_address, ack_packet, log)
                    duplicate_segs += 1
            elif received_packet.type == 'F':
                FINACK_packet = Packet('FA', current_server_seq_num + 1, received_packet.seq_num + 1)
                send_packet(s, client_address, FINACK_packet, log)
                FIN_packet = Packet('F', current_server_seq_num + 1, received_packet.seq_num + 1)
                send_packet(s, client_address, FIN_packet, log)
                receive_packet(s, log)
                break
    
    with open("Receiver_log.txt", "r") as logread:
        bytes_recv, data_segments_recv = get_final_stats(logread)
    with open("Receiver_log.txt", "a") as logwrite:                
        logwrite.write("Amount of Data Transferred: {}\n".format(bytes_recv))
        logwrite.write("Number of Data Segments Received: {}\n".format(data_segments_recv))
        logwrite.write("Number of Duplicate Segments received: {}\n".format(duplicate_segs))                
    
if __name__ == "__main__":
    receiver(sys.argv)
