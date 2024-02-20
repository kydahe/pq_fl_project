import zmq
import time

server_host = "tcp://localhost"
server_port = 5500

# SUB and PUB
context = zmq.Context()
socket = context.socket(zmq.SUB)
topicfilter = ""
server = "{}:{}".format(server_host, server_port)
socket.connect(server)
socket.setsockopt(zmq.SUBSCRIBE, b'')

print("connected")

msg = socket.recv()
print(msg)

# PULL and PUSH
# context = zmq.Context()
# socket = context.socket(zmq.PUSH)
# server = "{}:{}".format(server_host, server_port)
# socket.connect(server)

# print("connected")
# i = 0

# # time.sleep(10)
# while True:
#     time.sleep(2)
#     msg = "message {}".format(i)
#     socket.send_string(msg)
#     print("send")
#     i = i+1
#     if i > 10:
#         break


# REQ and REP
# context = zmq.Context()
# socket = context.socket(zmq.REQ)
# server = "{}:{}".format(server_host, server_port)
# socket.connect(server)

# print("connected")
# i = 0

# # time.sleep(10)
# while True:
#     time.sleep(2)
#     msg = "message {}".format(i)
#     socket.send_string(msg)
#     print("send")
#     msg = socket.recv_string()
#     print(msg)
#     i = i+1
#     if i > 10:
#         break
    