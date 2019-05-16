import signal
import socket
import threading
import time
import os
import sys

MAX_CACHE_BUFFER = 3
CACHE_DIR = "./cache"


class Server:
    def __init__(self, config):
        # Shutdown on Ctrl+C
        self.config = config
        signal.signal(signal.SIGINT, self.shutdown)
        print(
            '----------------------------------------------This is start------------------------------------------------')
        # A pair (host, port) is used for the AF_INET / SOCK_STREAM means that it is a TCP socket.
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # bind the socket to public host 127.0.0.1 and port 12345
        self.serverSocket.bind((config['HOST_NAME'], config['BIND_PORT']))
        # enable a server to accept connection/ number is specifies the number of unaccepted connections that the system
        # will allow before refusing new connections
        self.serverSocket.listen(1000)
        # keep track which file is locked
        self.locks = {}
        # remove all the cached file in cache folder
        for file in os.listdir(CACHE_DIR):
            os.remove(CACHE_DIR + "/" + file)

        while True:
            # accept a connection
            # return value is a pair (conn, address) where conn is a new socket object usable to send and receive data on the connection,
            # and address is the address bound to the socket on the other end of the connection.
            (clientSocket, client_address) = self.serverSocket.accept()
            print("This is client address", client_address)
            client_data = clientSocket.recv(4096)
            # multi-thread implementation
            # constructor for the thread target is the callable object to be invoked by the run() method. Defaults to
            # None, meaning nothing is called. name is the thread name.
            # args is the argument tuple for the target invocation.
            # Defaults to ().
            d = threading.Thread(target=self.proxy_thread, args=(clientSocket, client_address, client_data))
            # set the thread run in to daemon
            d.setDaemon(True)
            d.start()
        self.shutdown(0, 0)

    def shutdown(self, signum, frame):
        """ Handle the exiting server. Clean all traces """
        print("WARNING", -1, 'Shutting down gracefully...')
        main_thread = threading.currentThread()  # Wait for all clients to exit
        for t in threading.enumerate():
            if t is main_thread:
                continue
                print(("FAIL", -1, 'joining ' + t.getName()))
            t.join()
            self.serverSocket.close()
        sys.exit(0)

    def proxy_thread(self, conn, client_addr, client_data):
        print("proxy_thread is running")
        headers = self.getHeaderDetails(client_data)

        if not headers:
            print ("no any details", client_data)
            conn.close()
            return

        """
            Here we can check whether request is from outside the campus area or not.
            We have IP and port to which the request is being made.
            We can send error message if required.
        """

        if headers["server_url"] in self.config["BLOCKED_URL"]:
            print ("Block status : ")
            conn.send("HTTP/2.0 404 Not Found\r\n".encode("utf-8"))
            conn.send("content-type: text/html; charset=UTF-8\r\n".encode("utf-8"))
            conn.send("referrer-policy: no-referrer\r\n".encode("utf-8"))
            conn.send("content-length: 1568\r\n".encode("utf-8"))
            conn.send("\r\n\r\n".encode("utf-8"))

        elif headers["method"] == "GET":
            headers = self.get_cache_info(headers)
            if headers["mutate_time"]:
                headers = self.check_modified(headers)
            self.request(conn, client_addr, headers)
        conn.close()
        print (client_addr, "proxy_thread is ended")

    def getHeaderDetails(self, client_data):
        print("Parse details is running...")
        try:
            #Array of Request header contain each line
            headerList = client_data.decode("utf-8").splitlines()
            # the array have '' in the last element, like a signal of ending to the server, we have to remove it
            headerList.remove('')
            # request method and url in 3 element array eg. GET http://sing.cse.ust.hk/ HTTP/1.1
            methodAndUrl = headerList[0].split()
            # get URL
            url = methodAndUrl[1]

            # get starting url position and get the url
            url_pos = url.find("://")
            print("url_pos", url_pos)
            if url_pos != -1:
                protocol = url[:url_pos]
                url = url[(url_pos + 3):]
            else:
                protocol = "http"

            # find starting position of the path url(remove server url)
            path_pos = url.find("/")
            print("path_pos", path_pos)
            if path_pos == -1:
                path_pos = len(url)

            # find the port number position
            # if we do not find port, then set the default port to 80 and server url is before the path position
            port_pos = url.find(":")
            if port_pos == -1:
                server_port = 80
                server_url = url[:path_pos]
            else:
                server_port = int(url[(port_pos + 1):path_pos])
                server_url = url[:port_pos]


            # build up request for server
            methodAndUrl[1] = url[path_pos:]
            # without server url
            headerList[0] = ' '.join(methodAndUrl)
            client_data = "\r\n".join(headerList) + '\r\n\r\n'
            print("Parse details is end. Returning.....")
            return {"server_port": server_port, "server_url": server_url, "url": url, "client_data": client_data, "protocol": protocol, "method": methodAndUrl[0]}

        except Exception as e:
            print (e)
            print
            return None

    def get_cache_info(self, headers):
        print("get_cache_info is running")
        self.acquire_lock(headers["url"])
        fileurl = headers["url"]
        if fileurl.startswith("/"):
            fileurl = fileurl.replace("/", "", 1)
        # remove "/" to avoid the system think it is a directory path
        cache_path = CACHE_DIR + "/" + fileurl.replace("/", "_")
        # checking the cache whether have this file
        if os.path.isfile(cache_path):
            #change to GMT
            mutate_time = time.strptime(time.ctime(os.path.getmtime(cache_path) - 28800), "%a %b %d %H:%M:%S %Y")
            headers["mutate_time"] = mutate_time
            headers["cache_path"] = cache_path
        else:
            headers["cache_path"] = cache_path
            headers["mutate_time"] = None

        self.release_lock(headers["url"])
        print("get catch details is ended")
        return headers

    def acquire_lock(self, filePath):
        print ("lock is call")
        if filePath in self.locks:
            lock = self.locks[filePath]
        else:
            lock = threading.Lock()
            self.locks[filePath] = lock
        lock.acquire()
        print("return from lock")

    # unlock fileurl
    def release_lock(self, filePath):
        print("leave_access is calling")
        if filePath in self.locks:
            lock = self.locks[filePath]
            lock.release()
        else:
            print("nothing")
            #sys.exit()
        print("return from leave access")

    # insert the header
    def check_modified(self, headers):
        print("insert_if_modified is calling")
        headersList = headers["client_data"].splitlines()
        headersList.remove('')
        print("This is adding the header for the time information", type(headers["mutate_time"]))
        headersList.append("If-Modified-Since: " + time.strftime("%a, %d %b %Y %H:%M:%S GMT", (headers["mutate_time"])))
        headers["client_data"] = "\r\n".join(headersList) + "\r\n\r\n"
        print("insert if modified is ended")
        return headers

    # serve get request
    def request(self, client_socket, client_addr, headers):
        try:
            print("server_get is calling")
            cache_path = headers["cache_path"]
            mutate_time = headers["mutate_time"]
            #add the time interval that no need to send request again for 304
            if headers["mutate_time"] and time.mktime(time.gmtime()) - time.mktime(headers["mutate_time"]) <= 50:
                print("This is current GMT TIME")
                print(time.mktime(time.gmtime()) - time.mktime(headers["mutate_time"]))
                print ("returning cached file" + cache_path + "to " + str(client_addr))
                self.acquire_lock(headers["url"])
                f = open(cache_path, 'rb')
                chunk = f.read(self.config['BUFFER_SIZE'])
                while chunk:
                    client_socket.send(chunk)
                    chunk = f.read(self.config['BUFFER_SIZE'])
                f.close()
                self.release_lock(headers["url"])
                return
            else:

                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.connect((headers["server_url"], headers["server_port"]))
                print("Sending the file to server to check the file is modified or not... ", headers["client_data"])

                server_socket.send(headers["client_data"].encode('utf-8'))
                reply = server_socket.recv(self.config['BUFFER_SIZE'])
                print("Reply from server....................", reply, headers["cache_path"] )
                if mutate_time and "304 Not Modified" in reply.decode("utf-8"):
                    print ("returning cached file" + cache_path + "to " + str(client_addr))
                    self.acquire_lock(headers["url"])
                    f = open(cache_path, 'rb')
                    chunk = f.read(self.config['BUFFER_SIZE'])
                    while chunk:
                        client_socket.send(chunk)
                        chunk = f.read(self.config['BUFFER_SIZE'])
                    f.close()
                    self.release_lock(headers["url"])
                else:
                    print ("caching file while serving " + cache_path + "to" + str(client_addr))
                    self.get_space_for_cache(headers["url"])
                    self.acquire_lock(headers["url"])
                    f = open(cache_path, "wb")
                    # print len(reply), reply
                    while len(reply):
                        print(
                            "---------------------------------------------writing the file to the cache---------------------------")
                        client_socket.send(reply)
                        f.write(reply)
                        reply = server_socket.recv(self.config['BUFFER_SIZE'])
                        # print len(reply), reply
                    f.close()
                    self.release_lock(headers["url"])
                    client_socket.send("\r\n\r\n".encode('utf-8'))
                server_socket.close()
                client_socket.close()
                print("server get is ended")
                return

        except Exception as e:
            server_socket.close()
            client_socket.close()
            print (e)
            return

    def get_space_for_cache(self, fileurl):
        print("Function get_space_for_cache is calling", fileurl)
        cache_files = os.listdir(CACHE_DIR)
        # make decision of delete the cache the file to release space
        if len(cache_files) < MAX_CACHE_BUFFER:
            return
        # lock the file
        for file in cache_files:
            self.acquire_lock(file)

        print("This is file to remove")
        cache_path = CACHE_DIR + "/"
        file_to_del = ""
        lar_time_diff = 0
        now = time.time()
        print("Before remove", type(cache_files), cache_files)
        for file in cache_files:
            #mutate_time = time.strptime(time.ctime(os.path.getmtime(cache_path + file) - 28800), "%a %b %d %H:%M:%S %Y")
            if now - os.path.getmtime(cache_path + file) > lar_time_diff:
                file_to_del = file
                lar_time_diff = now - os.path.getmtime(cache_path + file)
            print("This is for loop calling", file, os.path.getmtime(cache_path + file), time.time())

        print("Remove this file", CACHE_DIR + "/" + file_to_del)
        os.remove(CACHE_DIR + "/" + file_to_del)
        print("After remove", cache_files)
        for file in cache_files:
            self.release_lock(file)


if __name__ == "__main__":
    # creating the instance of the server class
    server = Server(
        config={'HOST_NAME': '127.0.0.1', 'BIND_PORT': 65535, 'MAX_REQUEST_LEN': 1000, 'CONNECTION_TIMEOUT': 1000,
                "BLOCKED_URL": 'http://sing.cse.ust.hk/', 'BUFFER_SIZE': 4096})
