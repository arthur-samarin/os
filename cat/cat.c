#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(void) {
  ssize_t bytesRead;
  char buffer[4 * 1024];
  while ((bytesRead = read(STDIN_FILENO, buffer, sizeof(buffer))) > 0) {
    ssize_t bytesWrittenTotal = 0;
    while (bytesWrittenTotal < bytesRead) {
      ssize_t bytesWritten = write(STDOUT_FILENO, buffer + bytesWrittenTotal, bytesRead - bytesWrittenTotal);
      if (bytesWritten > 0) {
        bytesWrittenTotal += bytesWritten;
      } else {
        if (bytesWrittenTotal < 0) {
          fprintf(stderr, "Write error occured: %s\n", strerror(errno));
          return 1;
        } else {
          fprintf(stderr, "Can't write more for unknown reason\n");
          return 1;
        }
      }
    }
  }

  if (bytesRead == -1) {
      fprintf(stderr, "Read error occured: %s\n", strerror(errno));
      return 1;
  }
  return 0;
}
