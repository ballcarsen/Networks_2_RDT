import Network
import argparse
from time import sleep
import hashlib
import time


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    length_Ack_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_S, ack = 0):
        self.seq_num = seq_num
        self.msg_S = msg_S
        self.ack = ack

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        ack = int(byte_S[Packet.length_S_length + Packet.seq_num_S_length: Packet.length_S_length + Packet.seq_num_S_length + Packet.length_Ack_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length + Packet.length_Ack_length :]
        return self(seq_num, msg_S, ack)


    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        ack_num_S = str(self.ack).zfill(self.length_Ack_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + len(ack_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+ack_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + ack_num_S + checksum_S + self.msg_S


    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        ack_num_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.length_S_length + Packet.seq_num_S_length + Packet.length_Ack_length]
        checksum_S = byte_S[Packet.seq_num_S_length + Packet.seq_num_S_length +Packet.length_Ack_length : Packet.length_Ack_length+Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.length_Ack_length+Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]

        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+ack_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S


class RDT:
    ## latest sequence number used in a packet
    seq_num = 0
    received_num = -1
    ## buffer of bytes read from network
    byte_buffer = ''

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
        self.sent_pck = Packet(0, 'hello')
        self.received_pck = Packet(0, 'hello')
        self.sent_seq_num = 1
        self.wf_ack = False
        self.got_ack = False

    def disconnect(self):
        self.network.disconnect()

    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())

    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration


    def rdt_2_1_send(self, msg_S):
        self.byte_buffer = ''
        print("\nSending packet using RDT 2.1")
        p = Packet(self.seq_num, msg_S)
        self.last_msg = p
        self.seq_num += 1

        self.network.udt_send(p.get_byte_S())
        #keep extracting packets - if reordered, could get more than one
        while True:
            self.byte_buffer += self.network.udt_receive()
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                continue #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                continue #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string

            try:
                p_rec = Packet.from_byte_S(self.byte_buffer[0:length])
                self.byte_buffer = self.byte_buffer[length:]

                if p_rec.ack == 1:

                    if p_rec.seq_num == 1: # Positive Ack
                        print("Received an ACK for our message");
                        return
                    else: # Nak
                        print("Received a NAK for our message, resending")
                        # Resend Message
                        self.network.udt_send(p.get_byte_S())
                else: # Message
                    if p_rec.seq_num <= self.received_num:
                        print("Received a duplicate message\n")
                        ack = Packet(1, 'ack msg', 1)
                        self.network.udt_send(ack.get_byte_S())
                    else:
                        print("Received a new message, not ready for it, sending NAK")

                        # POINT OF INTEREST
                        # If we are recieving new messages, we can actually just want to
                        # respond to them with NAKs, forcing the sender to keep sending us it.
                        # The value of this is that we can essentially keep pushing back their
                        # new messages until we finally get our original ACK we have been waiting
                        # for. I think this solved all of our issues...
                        nak = Packet(0, 'ack msg', 1)
                        self.network.udt_send(nak.get_byte_S())
            except RuntimeError:
                print("Received a corrupt packet, resending")
                self.network.udt_send(p.get_byte_S())
                self.byte_buffer = self.byte_buffer[length:]

    def rdt_2_1_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string

            # Not corrupt
            try:
                print('\nReceived a packet using RDT 2.1')
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                self.byte_buffer = self.byte_buffer[length:]

                if p.ack == 1:
                    if(p.seq_num == 1):
                        print('Received an ACK, ignoring it (already a receiver)')
                    else:
                        print('Received a NAK, resending last message')
                        self.network.udt_send(self.last_msg.get_byte_S())
                    return None
                if p.seq_num <= self.received_num:
                    print('Received a duplicate packet, resending ACK')
                    ack = Packet(1, 'ack msg', 1)
                    self.network.udt_send(ack.get_byte_S())
                    ret_S = None
                else:
                    print('Received a new non-corrupt message, sending ACK')
                    self.received_num = p.seq_num
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    # remove the packet bytes from the buffer
                    # Send ack packet
                    ack = Packet(1, 'ack msg', 1)
                    self.network.udt_send(ack.get_byte_S())
                    # if this was the last packet, will return on the next iteration
                # Send positive ACK
            except RuntimeError:
                # Check with jordan what we should do if the ack is corrupt? Does it matter, right now I think a corrupt
                # Ack defaults to resending the packet.
                print('Received packet is corrupt, sending a NAK');
                nak = Packet(0, 'ack msg', 1)
                self.network.udt_send(nak.get_byte_S())
                self.byte_buffer = self.byte_buffer[length:]
                return None


    def rdt_3_0_send(self, msg_S, resend = False):
        self.byte_buffer = ''
        print("\nSending packet using RDT 3.0")
        p = Packet(self.seq_num, msg_S)
        self.last_msg = p
        self.seq_num += 1

        self.network.udt_send(p.get_byte_S())
        sent_time = time.time()
        # keep extracting packets - if reordered, could get more than one
        while True:
            # Timeout: resend message
            if sent_time + .1 < time.time():
                print('Timed out, resending message')
                sent_time = time.time()
                self.network.udt_send(p.get_byte_S())
                continue
            self.byte_buffer += self.network.udt_receive()
            # check if we have received enough bytes
            if (len(self.byte_buffer) < Packet.length_S_length):
                continue  # not enough bytes to read packet length
            # extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                continue  # not enough bytes to read the whole packet
            # create packet from buffer content and add to return string
            try:
                p_rec = Packet.from_byte_S(self.byte_buffer[0:length])
                self.byte_buffer = self.byte_buffer[length:]
                if p_rec.ack == 1:
                    if p_rec.seq_num == 1:  # Positive Ack
                        print('Received an ACK')
                        return
                    else:  # Nak
                        print('Received a NAK')
                        # Resend Message
                        sent_time = time.time()
                        self.network.udt_send(p.get_byte_S())
                else:  # Message

                    if p_rec.seq_num <= self.received_num:
                        print('Received a duplicate message, resending ACK')
                        ack = Packet(1, 'ack msg', 1)
                        self.network.udt_send(ack.get_byte_S())
                    else:
                        print('Received a new message while sending, sending NAK')

                        # POINT OF INTEREST
                        # If we are recieving new messages, we can actually just want to
                        # respond to them with NAKs, forcing the sender to keep sending us it.
                        # The value of this is that we can essentially keep pushing back their
                        # new messages until we finally get our original ACK we have been waiting
                        # for. I think this solved all of our issues...
                        print("...refuse to recognize it by sending a NAK.");
                        nak = Packet(0, 'ack msg', 1)
                        self.network.udt_send(nak.get_byte_S())
            except RuntimeError:
                print('Received a corrupt packet, resending message')
                sent_time = time.time()
                self.network.udt_send(p.get_byte_S())
                self.byte_buffer = self.byte_buffer[length:]

    def rdt_3_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        # keep extracting packets - if reordered, could get more than one
        while True:
            # check if we have received enough bytes
            if (len(self.byte_buffer) < Packet.length_S_length):
                return ret_S  # not enough bytes to read packet length
            # extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S  # not enough bytes to read the whole packet
            # create packet from buffer content and add to return string

            print('\nRDT 3.0 has recieved a packet');
            # Not corrupt
            try:
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                self.byte_buffer = self.byte_buffer[length:]

                if p.ack == 1:
                    if(p.seq_num == 1):
                        print('Received an ACK, ignoring it (already a receiver)')
                    else:
                        print('Received a NAK, resending last message')
                        self.network.udt_send(self.last_msg.get_byte_S())
                    return None

                if p.seq_num <= self.received_num:
                    print('Received a duplicate message, resending ACK')
                    ack = Packet(1, 'ack msg', 1)
                    self.network.udt_send(ack.get_byte_S())
                    ret_S = None
                else:
                    self.received_num = p.seq_num
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    # remove the packet bytes from the buffer
                    # Send ack packet
                    print('Received a new message, sending ACK')
                    ack = Packet(1, 'ack msg', 1)
                    self.network.udt_send(ack.get_byte_S())
                    # if this was the last packet, will return on the next iteration
                    # Send positive ACK
            except RuntimeError:
                # Check with jordan what we should do if the ack is corrupt? Does it matter, right now I think a corrupt
                # Ack defaults to resending the packet.
                print('Received a corrupt packet, sending NAK')
                nak = Packet(0, 'ack msg', 1)
                self.network.udt_send(nak.get_byte_S())
                self.byte_buffer = self.byte_buffer[length:]
                return None


if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()


    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
