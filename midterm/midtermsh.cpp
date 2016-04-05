#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <string>
#include <algorithm>
#include <array>
#include <sys/wait.h>
#include <assert.h>

using namespace std;

static volatile bool sigint_received = false;

void handle_error(const char* descr) {
    perror(descr);
    _exit(1);
}

void write_no_intr(const char* str) {
    size_t len = strlen(str);
    while (len > 0) {
        ssize_t r = write(STDOUT_FILENO, str, len);
        if (r >= 0) {
            len -= r;
            str += r;
        } else if (errno != EINTR) {
            handle_error("write");
        }
    }
}

struct buffered_reader {
    int fd;
    vector<char> buffer;

    buffered_reader(int fd) : fd(fd) {

    }

    bool read_line(std::string& result) {
        ssize_t len;
        array<char, 16> rbuffer;

        while (true) {
            len = read(STDIN_FILENO, rbuffer.begin(), rbuffer.size());

            if (len > 0) {
                auto rend = rbuffer.begin() + len;
                auto lf_ptr = std::find(rbuffer.begin(), rend, '\n');
                if (lf_ptr != rbuffer.end()) {
                    // LF reached
                    buffer.insert(buffer.end(), rbuffer.begin(), lf_ptr);
                    result = std::string(buffer.begin(), buffer.end());

                    buffer.clear();
                    buffer.insert(buffer.end(), lf_ptr + 1, rend);
                    return true;
                } else {
                    buffer.insert(buffer.end(), rbuffer.begin(), rend);
                }
            } else if (len == 0) {
                // EOF
                return false;
            } else if (errno != EINTR) {
                handle_error("read");
            }
        }

        // Never reached
        return false;
    }
};

struct command {
    vector<string> args;
    pid_t pid = -1;
    bool running = false;

    command(vector<string> args) : args(args) {
    }
};

vector<string> split(const std::string& str, char delim) {
    vector<string> args;
    auto c = str.begin();
    while (c != str.end()) {
        auto space_pos = std::find(c, str.end(), delim);
        if (space_pos != c) {
            args.emplace_back(c, space_pos);
        }
        c = space_pos != str.end() ? space_pos + 1 : str.end();
    }
    return args;
}

command parse_command(const std::string& str) {
    vector<string> args = split(str, ' ');
    return command(args);
}

vector<command> parse_commands(const std::string& str) {
    vector<command> commands;
    vector<string> v = split(str, '|');
    for (auto it = v.begin(); it != v.end(); ++it) {
        commands.push_back(parse_command(*it));
    }
    return commands;
}

void sighandler(int sig, siginfo_t *siginfo, void *context) {
    sigint_received = true;
}

void run_commands(vector<command> cmds) { 
    int next_in_fd = STDIN_FILENO;

    for (auto it = cmds.begin(); it != cmds.end(); ++it) {
        int in_fd = next_in_fd;
        int out_fd = STDOUT_FILENO;

        if (it != cmds.end() - 1) {
            // Not the last command
            int fpipe[2];
            if (pipe(fpipe) == -1) {
                handle_error("pipe");
            }

            out_fd = fpipe[1]; // Write end
            next_in_fd = fpipe[0]; // Read end
        }

        pid_t f = fork();
        if (f == -1) {
            handle_error("fork");
        }

        if (f != 0) {
            it->pid = f;
            it->running = true;
            if (in_fd != STDIN_FILENO) {
                if(close(in_fd) == -1) {
                    handle_error("parent close in");
                }
            }
            if (out_fd != STDOUT_FILENO) {
                if(close(out_fd) == -1) {
                    handle_error("parent close out");
                }
            }
        } else {
            // Child
            command &cmd = *it;
            char* args[cmd.args.size() + 1];
            for (size_t i = 0; i < cmd.args.size(); i++) {
                args[i] = const_cast<char*> (cmd.args[i].c_str());
            }
            args[cmd.args.size()] = 0;

            if (in_fd != STDIN_FILENO) {
                if(dup2(in_fd, STDIN_FILENO) == -1) {
                    handle_error("dup2 stdin");
                }
                if(close(in_fd) == -1) {
                    handle_error("child close temp in");
                }
            }
            if (out_fd != STDOUT_FILENO) {
                if(dup2(out_fd, STDOUT_FILENO) == -1) {
                    handle_error("dup2 stdout");
                }
                if(close(out_fd) == -1) {
                    handle_error("child close temp out");
                }
            }

            if (execvp(cmd.args[0].data(), args) == -1) {
                handle_error("exec");
            }
        }
    }

    for (auto it = cmds.begin(); it != cmds.end();) {
        int status;
        command& cmd = *it;
        if (!cmd.running) {
            continue;
        }

        pid_t p = waitpid(cmd.pid, &status, 0);
        if (p == -1) {
            if (errno == EINTR) {
                if (sigint_received) {
                    sigint_received = false;

                    for (auto it2 = it; it2 != cmds.end(); ++it2) {
                        kill(it2->pid, SIGINT);
                    }
                }
            } else {
                handle_error("waitpid");
            }
        } else {
            string msg = "midtermsh: ";
            msg += cmd.args[0];
            msg += " done [";
            msg += to_string(status);
            msg += "]\n";
            cmd.running = false;
            ++it;
            write_no_intr(msg.data());
        }
    }
}

int main(void) {
    struct sigaction action;
    memset(&action, 0, sizeof (action));
    action.sa_sigaction = &sighandler;
    action.sa_flags = SA_SIGINFO;

    if (sigaction(SIGINT, &action, NULL) < 0) {
        handle_error("sigaction");
    }

    buffered_reader reader(STDIN_FILENO);

    while (true) {
        write(STDOUT_FILENO, "$ ", 2);
        string line;
        bool ok = reader.read_line(line);
        if (!ok || line == "exit") {
            break;
        }
        vector<command> cmds = parse_commands(line);
        if (cmds.size() >= 1) {
            run_commands(cmds);
        }
    }

    return 0;
}
