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
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = ''

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
        self.sent_pck = Packet(0, 'hello')
        self.received_pck = Packet(0, 'hello')
        self.sent_seq_num = 1
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
        print("\nSending packet using RDT 2.1\n");
        p = Packet(self.seq_num, msg_S)
        self.sent_pck = p
        self.sent_seq_num = self.seq_num
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())

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

            try:
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                if p.ack == 1:
                    print('...recieved packet is an ACK w/ seq#=%s...' % p.seq_num);

                    if p.seq_num < self.seq_num:
                        print('...ACK is negative, seq is smaller than expected seq# %s...' % self.seq_num);
                        print('...therefore our message is resent and we wait for reception again.\n');

                        self.network.udt_send(self.sent_pck.get_byte_S())
                    else:
                        print('...ACK has valid sequence number.\n');
                    # need to remove ACK packet from the byte buffer.
                    self.byte_buffer = self.byte_buffer[length:]
                    return None
                else:
                    print('...recieved packet is a valid message w/ seq#=%s...' % p.seq_num);
                    self.received_pck = p
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    # remove the packet bytes from the buffer
                    self.byte_buffer = self.byte_buffer[length:]
                    # Send ack packet
                    print('...sending ACK w/ seq#=%s for recieved message.\n' % p.seq_num+1);
                    ack = Packet(p.seq_num + 1, 'ack msg', 1)
                    self.network.udt_send(ack.get_byte_S())
                    # if this was the last packet, will return on the next iteration

                # Send positive ACK
            except RuntimeError:
                # Check with jordan what we should do if the ack is corrupt? Does it matter, right now I think a corrupt
                # Ack defaults to resending the packet.
                print('...recieved packet is corrupt...');
                print('...sending a NAK to let sender know.\n');
                # Send negative ACK
                nak = Packet(self.seq_num, 'ack msg', 1)
                self.network.udt_send(nak.get_byte_S())
                self.byte_buffer = self.byte_buffer[length:]
                return None


    def rdt_3_0_send(self, msg_S, resend = False):
        # start a time out to resend data if nothing ack has been received.
        self.got_ack = False
        p = Packet(self.seq_num, msg_S)

        if not resend:
            self.sent_seq_num = self.seq_num
            self.seq_num += 1
            self.sent_pck = p

        self.network.udt_send(p.get_byte_S())

    def rdt_3_0_receive(self):
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

            try:
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                if p.ack == 1:
                    print('Received Ack')
                    self.got_ack = True
                    if p.seq_num < self.seq_num:
                        print('need to resend')
                        self.network.udt_send(self.sent_pck.get_byte_S())
                    self.byte_buffer = self.byte_buffer[length:]
                    return None
                else:
                    print('good packet')
                    self.received_pck = p
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    # remove the packet bytes from the buffer
                    self.byte_buffer = self.byte_buffer[length:]
                    # Send ack packet
                    print('sending ack')
                    self.network.udt_send(Packet(p.seq_num + 1, 'ack msg', 1).get_byte_S())
                    # if this was the last packet, will return on the next iteration

                # Send positive ACK
            except RuntimeError:
                # Check with jordan what we should do if the ack is corrupt? Does it matter, right now I think a corrupt
                # Ack defaults to resending the packet.
                print('corrupt')
                # Send negative ACK
                self.network.udt_send(Packet(self.seq_num, 'ack msg', 1).get_byte_S())
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
