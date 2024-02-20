import zmq
import time

host = "tcp://*"
port = 5500


# SUB and PUB
context = zmq.Context()
socket = context.socket(zmq.PUB)
socket.bind("{}:{}".format(host, port))

time.sleep(10)
socket.send(b"topic1 content")
# print(msg)

# PULL and PUSH
# context = zmq.Context()
# socket = context.socket(zmq.PULL)
# socket.bind("{}:{}".format(host, port))
# print("listening ...")

# i = 0
# while True:
#     msg = socket.recv_string()

#     print(msg)
#     i = i+1

# REQ and REP
# context = zmq.Context()
# socket = context.socket(zmq.REP)
# socket.bind("{}:{}".format(host, port))
# print("listening ...")

# i = 0
# while True:
#     msg = socket.recv_string()

#     print(msg)

#     socket.send_string("Received {}".format(i))
#     print("send")
#     i = i+1