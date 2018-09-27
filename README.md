# SimpleTCP
An basic implementation of the TCP protocol using UDP packets.

This repo contains both the receiver and sender code.

The receiver listens for a client to connect to it effectively acting as a server. The sender connects to it allowing the receiver to gain its address information.

The client begins the three way handshake using a randomized client ISN and the server participates to return its own ISN.

The client divides the outfile (the file to be transferred) into payloads of MSS byte sizes. The client then appends these payloads to their respective packets.

The client calculates the window to send the packets and then sends those packets. It waits for all acknowledgements for every packet in that window before proceeding. Every time when the sender receives an acknowledgement packet that acknowledges new bytes, the sender will reset its internal timer. If the client timeouts, it simply resends the packet with the lowest unacknowledged sequence number and resets the timer. The timer runs on a seperate thread to run in parellel with the event loop.

The receiver processes each data packet. If the packet is a ack packet, it just ignores it. If the packet is a data packet, then it will write to the outfile if it is in order and if not, it will place in the buffer. If the receiver has received the segment before, it simply sends an ACK packet to the client to get the expected data packet with the correct in sequence number.

When the window is fully processed, the sender repeats the procedure where it calculates the window and send the packets for that window until the every byte of the entire outfile has been acknowledged by the receiver. 

To finalise the process, the client ends with the FIN three way handshake and processes all of the statistics required and appends them to the log list.

Features

TCP Features Implemented:
- Fast retransmit
- Three way handshake for connection establishment and four segment teardown
- Sender single timer
- Re-iteration of simplified TCP sender as requested
- MWS window restrictions
- Packet buffer
- Cumulative acknowledgements

General Features Implemented:
- Packet object class to represent an STP packet
- Complementary logfile writing when sending and receiving packets
- Sender timer on a seperate thread for parellelism
