#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

static volatile int received_signo = -1;
static volatile int source_pid;

void sighandler(int sig, siginfo_t *siginfo, void *context)
{
  received_signo = sig;
  source_pid = siginfo->si_pid;
}


void handle_error(const char* descr) {
  perror(descr);
  _exit(1);
}

int main(void) {
  struct sigaction action;
  memset (&action, 0, sizeof(action));
  action.sa_sigaction = &sighandler;
  action.sa_flags = SA_SIGINFO;

  if (sigaction(SIGUSR1, &action, NULL) < 0 || sigaction(SIGUSR2, &action, NULL) < 0) {
    handle_error("sigaction");
  }

  sleep(10);
  if (received_signo >= 0) {
    printf("%s from %d\n", received_signo == SIGUSR1 ? "SIGUSR1" : "SIGUSR2", source_pid);
  } else {
    printf("No signals were caught\n");
  }

  return 0;
}
