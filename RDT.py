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
        print("\nSending packet using RDT 2.1...")
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
            print("...received a response...")
            try:
                p_rec = Packet.from_byte_S(self.byte_buffer[0:length])
                self.byte_buffer = self.byte_buffer[length:]
                print("...response is not corrupt...")
                if p_rec.ack == 1:
                    print("...response is an acknowledgement...")
                    print("...expecting ACK if seq#=1...")
                    if p_rec.seq_num == 1: # Positive Ack
                        print("...response is an ACK w/ seq#=%s..." % p_rec.seq_num)
                        print("...message received, ending send method.");
                        return
                    else: # Nak
                        print("...response is a NAK w/ seq#=%s..." % p_rec.seq_num)
                        print("...resending our message.");
                        # Resend Message
                        self.network.udt_send(p.get_byte_S())
                else: # Message
                    print("...response is a message...");
                    print("...if seq # less than %s, its already received..." % self.received_num)
                    if p_rec.seq_num <= self.received_num:
                        print("...message has seq#=%s, so we have already received it..." % p_rec.seq_num);
                        print("...removing from byte buffer and continuing send method...");
                        ack = Packet(1, 'ack msg', 1)
                        self.network.udt_send(ack.get_byte_S())
                    else:
                        print("...message has seq#=%s, so we have not previously received it..." % p_rec.seq_num);

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
                print("...response is corrupt...");
                print("...resending our message.");
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

            print('\nRDT 2.1 has recieved a packet...');
            # Not corrupt
            try:
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                self.byte_buffer = self.byte_buffer[length:]

                if p.ack == 1:
                    print('...receieved an ack...')
                    if(p.seq_num == 1):
                        print('...ack, ignore...')
                    else:
                        print('...nak, resend our last data')
                        self.network.udt_send(self.last_msg.get_byte_S())
                    return None

                print('...recieved packet is a valid message w/ seq#=%s...' % p.seq_num);
                if p.seq_num <= self.received_num:
                    print('..duplicate packet.. with seq # %s and latest seq # of %s' % (p.seq_num,self.received_num))
                    ack = Packet(1, 'ack msg', 1)
                    self.network.udt_send(ack.get_byte_S())
                    ret_S = None
                else:
                    print('...non duplicate packet...')
                    self.received_num = p.seq_num
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    # remove the packet bytes from the buffer
                    # Send ack packet
                    print('...sending ACK w/ seq#=%d for recieved message.\n' % (int(p.seq_num)+1));
                    ack = Packet(1, 'ack msg', 1)
                    self.network.udt_send(ack.get_byte_S())
                    # if this was the last packet, will return on the next iteration
                # Send positive ACK
            except RuntimeError:
                # Check with jordan what we should do if the ack is corrupt? Does it matter, right now I think a corrupt
                # Ack defaults to resending the packet.
                print('...recieved packet is corrupt...');
                nak = Packet(0, 'ack msg', 1)
                self.network.udt_send(nak.get_byte_S())
                self.byte_buffer = self.byte_buffer[length:]
                return None


    def rdt_3_0_send(self, msg_S, resend = False):
        self.byte_buffer = ''
        print("\nSending packet using RDT 2.1...")
        p = Packet(self.seq_num, msg_S)
        self.last_msg = p
        self.seq_num += 1

        self.network.udt_send(p.get_byte_S())
        sent_time = time.time()
        # keep extracting packets - if reordered, could get more than one
        while True:
            # Timeout: resend message
            if sent_time + 2 < time.time():
                print('... timeout, resend message...')
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
            print("...received a response...")
            try:
                p_rec = Packet.from_byte_S(self.byte_buffer[0:length])
                self.byte_buffer = self.byte_buffer[length:]
                print("...response is not corrupt...")
                if p_rec.ack == 1:
                    print("...response is an acknowledgement...")
                    print("...expecting ACK if seq#=1...")
                    if p_rec.seq_num == 1:  # Positive Ack
                        print("...response is an ACK w/ seq#=%s..." % p_rec.seq_num)
                        print("...message received, ending send method.");
                        return
                    else:  # Nak
                        print("...response is a NAK w/ seq#=%s..." % p_rec.seq_num)
                        print("...resending our message.");
                        # Resend Message
                        sent_time = time.time()
                        self.network.udt_send(p.get_byte_S())
                else:  # Message
                    print("...response is a message...");
                    print("...if seq # less than %s, its already received..." % self.received_num)
                    if p_rec.seq_num <= self.received_num:
                        print("...message has seq#=%s, so we have already received it..." % p_rec.seq_num);
                        print("...removing from byte buffer and continuing send method...");
                        ack = Packet(1, 'ack msg', 1)
                        self.network.udt_send(ack.get_byte_S())
                    else:
                        print("...message has seq#=%s, so we have not previously received it..." % p_rec.seq_num);

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
                print("...response is corrupt...");
                print("...resending our message.");
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

            print('\nRDT 2.1 has recieved a packet...');
            # Not corrupt
            try:
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                self.byte_buffer = self.byte_buffer[length:]

                if p.ack == 1:
                    print('...receieved an ack...')
                    if (p.seq_num == 1):
                        print('...ack, ignore...')
                    else:
                        print('...nak, resend our last data')
                        self.network.udt_send(self.last_msg.get_byte_S())
                    return None

                print('...recieved packet is a valid message w/ seq#=%s...' % p.seq_num);
                if p.seq_num <= self.received_num:
                    print('..duplicate packet.. with seq # %s and latest seq # of %s' % (p.seq_num, self.received_num))
                    ack = Packet(1, 'ack msg', 1)
                    self.network.udt_send(ack.get_byte_S())
                    ret_S = None
                else:
                    print('...non duplicate packet...')
                    self.received_num = p.seq_num
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    # remove the packet bytes from the buffer
                    # Send ack packet
                    print('...sending ACK w/ seq#=%d for recieved message.\n' % (int(p.seq_num) + 1));
                    ack = Packet(1, 'ack msg', 1)
                    self.network.udt_send(ack.get_byte_S())
                    # if this was the last packet, will return on the next iteration
                    # Send positive ACK
            except RuntimeError:
                # Check with jordan what we should do if the ack is corrupt? Does it matter, right now I think a corrupt
                # Ack defaults to resending the packet.
                print('...recieved packet is corrupt...');
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
