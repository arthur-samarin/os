#include <iostream>
#include <list>
#include <unistd.h>
#include <cstddef>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <cstring>
#include <vector>
#include <array>
#include <assert.h>
#include <fcntl.h>
#include <signal.h>

#define container_of( ptr, type, member ) \
   ( \
      { \
         const decltype( ((type *)0)->member ) *__mptr = (ptr); \
         (type *)( (char *)__mptr - offsetof( type, member ) ); \
      } \
   )

const static size_t TRANSFER_CHUNK_SIZE = 1024;

class errno_exception {
public:
    errno_exception(std::string description): description(description), err(errno) {

    }

    std::string description;
    int err;
};

class file_descriptor {
public:
    file_descriptor(): fd(-1) {}
    file_descriptor(int fd) : fd(fd) {
        if (fd == -1) {
            throw errno_exception("Unable to create FD");
        }
    }

    file_descriptor(const file_descriptor& rhs) = delete;
    file_descriptor& operator=(const file_descriptor& rhs) = delete;

    file_descriptor(file_descriptor&& rhs): fd(-1) {
        swap(*this, rhs);
    };
    file_descriptor& operator=(file_descriptor&& rhs) noexcept {
        swap(*this, rhs);
        return *this;
    };

    ~file_descriptor() {
        close();
    }

    friend void swap(file_descriptor& a, file_descriptor& b) noexcept;
    friend size_t read(file_descriptor& f, char* buffer, size_t max);
    friend size_t write(file_descriptor& f, char* buffer, size_t max);
    friend void close(file_descriptor& f) noexcept;

    int getfd() const noexcept {
        return fd;
    }

    void close() {
        if (fd != -1) {
            ::close(fd);
            fd = -1;
        }
    }
private:
    int fd;
};

void swap(file_descriptor& a, file_descriptor& b) noexcept {
    std::swap(a.fd, b.fd);
}

size_t read(file_descriptor &f, char *buffer, size_t max) {
    if (f.getfd() == -1) {
        return 0;
    }

    ssize_t s;
    do {
        s = ::read(f.fd, buffer, max);
        if (s == -1 && errno != EINTR) {
            throw errno_exception("read");
        }
    } while (s == -1);

    return (size_t) s;
}

size_t write(file_descriptor &f, char *buffer, size_t max) {
    ssize_t s;
    do {
        s = ::write(f.fd, buffer, max);
        if (s == -1 && errno != EINTR) {
            throw errno_exception("write");
        }
    } while (s == -1);
    return (size_t) s;
}

void close(file_descriptor &f) noexcept {
    if (f.fd != -1 && close(f.fd) != -1) {
        f.fd = -1;
    }
}

class tcp_socket {
public:
    tcp_socket(): fd() {

    }
    tcp_socket(file_descriptor&& fd): fd(std::move(fd)) {

    }
    tcp_socket(int options): fd(socket(AF_INET, SOCK_STREAM | options, 0)) {

    }

    template<typename... Args> auto write(Args&&... args) { return ::write(fd, std::forward<Args>(args)...); }
    template<typename... Args> auto read(Args&&... args) { return ::read(fd, std::forward<Args>(args)...); }
    template<typename... Args> auto close(Args&&... args) { ::close(fd, std::forward<Args>(args)...); }

    tcp_socket(const tcp_socket& rhs) = delete;
    tcp_socket& operator=(const tcp_socket& rhs) = delete;

    tcp_socket(tcp_socket&& rhs) noexcept {
        swap(fd, rhs.fd);
    };
    tcp_socket& operator=(tcp_socket&& rhs) noexcept {
        swap(fd, rhs.fd);
        return *this;
    };

    const file_descriptor& getFd() const {
        return fd;
    }
private:
    file_descriptor fd;
};

class acceptor {
public:
    acceptor(): fd() {

    }
    acceptor(file_descriptor&& fd): fd(std::move(fd)) {

    }

    acceptor(uint16_t port, int options): fd(socket(AF_INET, SOCK_STREAM | options, 0)) {
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(fd.getfd(), (sockaddr *)&addr, sizeof(addr)) == -1)
        {
            throw errno_exception("bind");
        }
        if (listen(fd.getfd(), 1) == -1) {
            throw errno_exception("listen");
        }
    }

    acceptor(const acceptor& rhs) = delete;
    acceptor& operator=(const acceptor& rhs) = delete;

    acceptor(acceptor&& rhs) noexcept {
        swap(fd, rhs.fd);
    };
    acceptor& operator=(acceptor&& rhs) noexcept {
        swap(fd, rhs.fd);
        return *this;
    };

    template<typename... Args> void close(Args&&... args) { ::close(fd, std::forward<Args>(args)...); }

    tcp_socket accept(int flags) {
        int sock_fd = accept4(fd.getfd(), nullptr, nullptr, flags);
        if(sock_fd == -1) {
            throw errno_exception("acceptor::accept");
        }
        return tcp_socket(file_descriptor(sock_fd));
    }

    const file_descriptor& getFd() const {
        return fd;
    }
private:
    file_descriptor fd;
};

class pseudoterminal {
public:
    pseudoterminal(): master_fd() {

    }

    pseudoterminal(file_descriptor&& fd): master_fd(std::move(fd)) {

    }

    pseudoterminal(int options): master_fd(posix_openpt(options)) {
        if (grantpt(master_fd.getfd()) == -1) {
            throw errno_exception("pseudoterminal(), grantpt");
        }
        if (unlockpt(master_fd.getfd()) == -1) {
            throw errno_exception("pseudoterminal(), unlockpt");
        }
    }

    template<typename... Args> auto write(Args&&... args) { return ::write(master_fd, std::forward<Args>(args)...); }
    template<typename... Args> auto read(Args&&... args) { return ::read(master_fd, std::forward<Args>(args)...); }
    template<typename... Args> auto close(Args&&... args) { ::close(master_fd, std::forward<Args>(args)...); }

    pseudoterminal(const pseudoterminal& rhs) = delete;
    pseudoterminal& operator=(const pseudoterminal& rhs) = delete;

    pseudoterminal(pseudoterminal&& rhs) noexcept {
        swap(master_fd, rhs.master_fd);
    };
    pseudoterminal& operator=(pseudoterminal&& rhs) noexcept {
        swap(master_fd, rhs.master_fd);
        return *this;
    };

    const file_descriptor& getMasterFd() const {
        return master_fd;
    }

    file_descriptor openSlave() const {
        char *name = ptsname(master_fd.getfd());
        if (name) {
            return file_descriptor(::open(name, O_RDWR));
        } else {
            throw errno_exception("pseudoterminal::openSlave, ptsname");
        }
    }
private:
    file_descriptor master_fd;
};

class epoll_group {
public:
    epoll_group(): fd() {

    }
    epoll_group(file_descriptor&& fd): fd(std::move(fd)) {

    }

    epoll_group(int options): fd(epoll_create1(options)) {}

    epoll_group(const epoll_group& rhs) = delete;
    epoll_group& operator=(const epoll_group& rhs) = delete;

    epoll_group(epoll_group&& rhs) noexcept {
        swap(fd, rhs.fd);
    };
    epoll_group& operator=(epoll_group&& rhs) noexcept {
        swap(fd, rhs.fd);
        return *this;
    };

    void registerFd(const file_descriptor &fdToListen, uint32_t events, void* data) {
        epoll_event event;
        event.events = events;
        event.data.ptr = data;
        if (epoll_ctl(fd.getfd(), EPOLL_CTL_ADD, fdToListen.getfd(), &event) == -1) {
            throw errno_exception("epoll_group::registerFd, epoll_ctl");
        }
    }

    void modifyRegistration(const file_descriptor &fdToListen, uint32_t events, void* data) {
        epoll_event event;
        event.events = events;
        event.data.ptr = data;
        if (epoll_ctl(fd.getfd(), EPOLL_CTL_MOD, fdToListen.getfd(), &event) == -1) {
            throw errno_exception("epoll_group::modifyRegistration, epoll_ctl");
        }
    }

    void removeRegistration(const file_descriptor &fdToListen) {
        epoll_event event;
        if (epoll_ctl(fd.getfd(), EPOLL_CTL_DEL, fdToListen.getfd(), &event) == -1) {
            throw errno_exception("epoll_group::removeRegistration, epoll_ctl");
        }
    }

    int nextEvents(epoll_event* events, int max) {
        int numEvents;
        do {
            numEvents = epoll_wait(fd.getfd(), events, max, -1);
            if (numEvents == -1 && errno != EINTR) {
                throw errno_exception("epoll_group::nextEvents, epoll_wait");
            }
        } while (numEvents == -1);

        return numEvents;
    }

    const file_descriptor& getFd() const {
        return fd;
    }

private:
    file_descriptor fd;
};

template<size_t capacity>
class cyclic_buffer {
public:
    size_t count() const {
        return size;
    }

    size_t availableSpace() const {
        return capacity - size;
    }

    bool isFull() const{
        return count() == capacity;
    }

    bool isEmpty() const {
        return count() == 0;
    }

    size_t write(std::string str) {
        return write(str.data(), str.size());
    }

    size_t write(const char *buf, size_t len) {
        size_t b = std::min(availableSpace(), len);

        size_t index = end;
        for (size_t i = 0; i < b; i++) {
            storage[index] = buf[i];
            index = (index + 1) % capacity;
        }

        end = index;
        size += b;

        return b;
    }

    size_t seek(char *dest, size_t maxLen) const {
        size_t b = std::min(maxLen, count());

        size_t index = start;
        for (size_t i = 0; i < b; i++) {
            dest[i] = storage[index];
            index = (index + 1) % capacity;
        }

        return b;
    }

    void skip(size_t len) {
        assert(len <= count());

        start = (start + len) % capacity;
        size -= len;
    }

    size_t read(char *dest, size_t len) {
        size_t b = seek(dest, len);
        skip(b);
        return b;
    }

private:
    std::array<char, capacity> storage;
    size_t start = 0;
    size_t end = 0;
    size_t size = 0;
};

enum epoll_tag {
    UNDEFINED, CONN_SOCKET, CONN_PIPE
};

class conn {
public:
    conn(tcp_socket &&socket) : socket(std::move(socket)) {

    }

    void startShell() {
        pty = pseudoterminal(O_RDWR | O_CLOEXEC);

        file_descriptor slaveFd = pty.openSlave();

        shellPid = fork();
        if (shellPid == -1) {
            throw errno_exception("fork");
        }

        if (shellPid == 0) {
            // Child
            setsid();

            dup2(slaveFd.getfd(), STDIN_FILENO);
            dup2(slaveFd.getfd(), STDOUT_FILENO);
            dup2(slaveFd.getfd(), STDERR_FILENO);
            slaveFd.close();

            if (execlp("sh", "sh", NULL) == -1) {
                perror("Can't start the shell");
                _exit(1);
            }
        } else {
            // Parent
            // slaveFd will be closed in destructor
        }
    }

    std::list<conn>::iterator position;

    tcp_socket socket;
    pseudoterminal pty;

    const epoll_tag tagSocket = CONN_SOCKET;
    const epoll_tag tagPipe = CONN_PIPE;

    pid_t shellPid;

    cyclic_buffer<1024> sendBuffer;
    cyclic_buffer<1024> receiveBuffer;

    bool socketReadReady = false;
    bool socketWriteReady = false;
    bool pipeReadReady = false;
    bool pipeWriteReady = false;

    bool pipeCloseHandled = false;
    bool pipeClosed = false;
    bool socketCloseHandled = false;
    bool socketRemoteClosed = false;
    bool errorOccurred = false;

    bool need_be_handled = false;
};

class server {
public:
    server(uint16_t port) : acc(port, SOCK_NONBLOCK | SOCK_CLOEXEC), group(0) {
        group.registerFd(acc.getFd(), EPOLLIN, &acc);
    }

    void run() {
        while (true) {
            const int max_events = 16;
            epoll_event events[max_events];

            int numEvents = group.nextEvents(events, max_events);

            connections_to_handle.clear();
            for (int i = 0; i < numEvents; ++i) {
                epoll_event &event = events[i];
                preHandleEvent(event);
            }

            handleUpdates();
        }
    }

    void preHandleEvent(epoll_event &event) {
        void *data = event.data.ptr;

        if (data == &acc) {
            if (event.events & EPOLLIN) {
                connections.emplace_back(acc.accept(SOCK_NONBLOCK | SOCK_CLOEXEC));

                try {
                    conn &conn = connections.back();
                    conn.startShell();

                    conn.position = connections.end();
                    --conn.position;

                    assert(&(*conn.position) == &conn);

                    group.registerFd(conn.socket.getFd(), EPOLLIN | EPOLLRDHUP, const_cast<epoll_tag*>(&conn.tagSocket));
                    group.registerFd(conn.pty.getMasterFd(), EPOLLIN, const_cast<epoll_tag*>(&conn.tagPipe));

                    printf("New connection!\n");
                } catch (const errno_exception& ex) {
                    fprintf(stderr, "Error accepting incoming connection, %s: %s", ex.description.data(), strerror(ex.err));
                    connections.pop_back();
                }
            }
        } else {
            epoll_tag& tag = *static_cast<epoll_tag*>(data);
            conn* cptr = nullptr;
            switch (tag) {
                case CONN_SOCKET:
                    cptr = container_of(&tag, conn, tagSocket);
                    break;
                case CONN_PIPE:
                    cptr = container_of(&tag, conn, tagPipe);
                    break;
                default:
                    fprintf(stderr, "Unknown epoll tag: %d\n", (int)tag);
                    return;
            }

            conn& c = *cptr;

            switch (tag) {
                case CONN_SOCKET:
                    if (event.events & (EPOLLERR | EPOLLHUP)) {
                        printf("Socket error\n");
                        handle_later(c, c.errorOccurred);
                    } else {
                        if (event.events & EPOLLRDHUP) {
                            handle_later(c, c.socketRemoteClosed);
                        }
                        if (event.events & EPOLLIN) {
                            handle_later(c, c.socketReadReady);
                        }
                        if (event.events & EPOLLOUT) {
                            handle_later(c, c.socketWriteReady);
                        }
                    }
                    break;
                case CONN_PIPE:
                    if (event.events & EPOLLERR) {
                        printf("Pipe error\n");
                        handle_later(c, c.errorOccurred);
                    } else {
                        if (event.events & EPOLLHUP) {
                            handle_later(c, c.pipeClosed);
                        }
                        if (event.events & EPOLLIN) {
                            handle_later(c, c.pipeReadReady);
                        }
                        if (event.events & EPOLLOUT) {
                            handle_later(c, c.pipeWriteReady);
                        }
                    }
                    break;
            }
        }
    }

    void handleUpdates() {
        for (conn* c : connections_to_handle) {
            c->need_be_handled = false;

            try {
                if (c->errorOccurred) {
                    destroyConnection(*c);
                    continue;
                }

                if (c->socketRemoteClosed) {
                    // Send all read data to pty

                    if (c->pipeClosed) {
                        destroyConnection(*c);
                        continue;
                    }

                    if (!c->socketCloseHandled) {
                        c->socketCloseHandled = true;

                        // Ignore pty IN
                        group.modifyRegistration(c->pty.getMasterFd(), EPOLLOUT, const_cast<epoll_tag*>(&c->tagPipe));
                    }

                    if (transferLeft(c->receiveBuffer, c->socket, c->pty)) {
                        destroyConnection(*c);
                    }

                } else if (c->pipeClosed) {
                    // Send all unsent data

                    if (!c->pipeCloseHandled) {
                        c->pipeCloseHandled = true;

                        // Don't receive HUP again
                        group.removeRegistration(c->pty.getMasterFd());

                        // Ignore socket IN
                        group.modifyRegistration(c->socket.getFd(), EPOLLOUT | EPOLLRDHUP, const_cast<epoll_tag*>(&c->tagSocket));
                    }

                    if(transferLeft(c->sendBuffer, c->pty, c->socket)) {
                        destroyConnection(*c);
                    }

                    continue;
                } else {
                    if (c->socketReadReady) {
                        // Network -> Receive buffer
                        c->socketReadReady = false;

                        transfer(c->socket, c->receiveBuffer);
                    }

                    if (c->pipeReadReady) {
                        // Pipe -> Send buffer
                        c->pipeReadReady = false;

                        transfer(c->pty, c->sendBuffer);
                    }

                    if (c->pipeWriteReady) {
                        // Receive buffer -> Pipe
                        c->pipeWriteReady = false;

                        transfer(c->receiveBuffer, c->pty);
                    }

                    if (c->socketWriteReady) {
                        // Send buffer -> Network
                        c->socketWriteReady = false;

                        transfer(c->sendBuffer, c->socket);
                    }

                    uint32_t ptyEvents =
                            (!c->sendBuffer.isFull() ? EPOLLIN : 0u) | (!c->receiveBuffer.isEmpty() ? EPOLLOUT : 0u);
                    uint32_t socketEvents =
                            (!c->sendBuffer.isEmpty() ? EPOLLOUT : 0u) | (!c->receiveBuffer.isFull() ? EPOLLIN : 0u) |
                            EPOLLRDHUP;

                    group.modifyRegistration(c->socket.getFd(), socketEvents, const_cast<epoll_tag *>(&c->tagSocket));
                    group.modifyRegistration(c->pty.getMasterFd(), ptyEvents, const_cast<epoll_tag *>(&c->tagPipe));

                    if (c->socketRemoteClosed || c->pipeClosed) {
                        destroyConnection(*c);
                        continue;
                    }
                }
            } catch (const errno_exception& ex) {
                fprintf(stdout, "Error while handling updates, %s: %s\n", ex.description.data(), strerror(ex.err));
                destroyConnection(*c);
            }
        }
    }

    template<size_t capacity, typename In, typename Out>
    bool transferLeft(cyclic_buffer<capacity>& buf, In& in, Out& out) {
        if (!buf.isEmpty()) {
            transfer(buf, out);
        } else {
            try {
                // read() throws exception if nothing can be read
                transfer(in, buf);

                // Or doesn't throw returning 0?
                return buf.isEmpty();
            } catch (const errno_exception& ex) {
                return true;
            }
        }
    }

    template<size_t capacity, typename In>
    void transfer(In& in, cyclic_buffer<capacity>& buf) {
        if (!buf.isFull()) {
            size_t availSpace = std::min(buf.availableSpace(), TRANSFER_CHUNK_SIZE);
            char buffer[TRANSFER_CHUNK_SIZE];
            size_t numRead = in.read(buffer, availSpace);
            buf.write(buffer, numRead);
        }
    }

    template<size_t capacity, typename Out>
    void transfer(cyclic_buffer<capacity>& buf, Out& out) {
        if (!buf.isEmpty()) {
            char buffer[TRANSFER_CHUNK_SIZE];
            size_t s = buf.seek(buffer, sizeof(buffer));
            size_t numWritten = out.write(buffer, s);
            buf.skip(numWritten);
        }
    }

    void handle_later(conn& c, bool& flag) {
        flag = true;
        if (!c.need_be_handled) {
            c.need_be_handled = true;
            connections_to_handle.push_back(&c);
        }
    }

    void destroyConnection(conn& c) {
        connections.erase(c.position);
        printf("Destroyed\n");
    }
private:
    acceptor acc;
    epoll_group group;
    std::list<conn> connections;

    std::vector<conn*> connections_to_handle;
};

void daemonize() {
    pid_t p = fork();
    
    if (p == -1) {
        throw errno_exception("fork");
    }
    
    if (p) {
        // Parent
        _exit(0);
    } else {
       if(setsid() == -1) {
          throw errno_exception("setsid");
       }
           
       p = fork();
       
       if (p == -1) {
           throw errno_exception("fork");
       }
       
       if (p) {
           _exit(0);
       } else {
           FILE *f = fopen("/tmp/rshd.pid", "w");
           if (f) {
               fprintf(f, "%d", getpid());
               fclose(f);
               // return to main
               return;
           } else {
               throw errno_exception("fopen"); 
           }
       }
    }
}

int main(int argc, char ** argv) {
    if (argc < 2) {
        printf("Usage: %s <port number>", argv[0]);
        return 1;
    }
    
    try {
        if (argc < 3 || strcmp("--no-daemon", argv[2]) != 0) {
            daemonize();
        }
        
        signal(SIGPIPE, SIG_IGN);
        signal(SIGCHLD, SIG_IGN);

        server srv((uint16_t) atoi(argv[1]));
        srv.run();
    } catch (const errno_exception& ex) {
        fprintf(stderr, "%s: %s", ex.description.data(), strerror(ex.err));
    }
    return 0;
}