#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

/* call a program and save the output
 *
 * @param cmd the command to run and its arguments
 * @param out the buffer to put the output in
 * @param len the size of the buffer
 *
 * @return the number of bytes read
 * anything past len bytes is discarded
 */
int capture_cmd_output(char *cmd[], char *out, int len) 
{
   int p[2];
   pid_t pid;
   int ret;
   int devnull=-1;
   int fp = 0;
   int bytes_read = 0;

   devnull = open("/dev/null", O_RDWR);
   if (devnull == -1) {
      return(-1);
   } 

   /* set up the pipe for communication */
   if (pipe(p) == -1) {
      return(-1);
   }


   pid = fork();

   switch (pid) {
      case -1:
         close(devnull);
         close(p[0]);
         close(p[1]);
         return(-1);
      case 0:
         dup2(devnull, 0);
         dup2(p[1], 1);
         dup2(p[1], 2);
         close(devnull);
         close(p[0]);
         close(p[1]);
         execv(cmd[0], cmd);
         exit (-1);
     default:
         break;

   }

   close(p[1]);

   while(!fp) {
      if (len) {
         ret = read(p[0], out, len);
         if (ret > 0) {
            out += ret;
            len -= ret;
            bytes_read += ret;
         } else {
            fp = 1;
         }
     } else {
        char buf[1024];
        /* the buffer filled, just disard the rest of the output */
        ret = read(p[0], buf, sizeof(buf));
        if (ret <= 0) { 
           fp = 1;
        }
     }
   }

   waitpid(pid, &ret, 0);
   close(p[0]);

   *(out++) = 0;

   return(bytes_read);
} 

#if 0
int main()
{
    char * cmd[3] = {"/bin/ps", "-ef", NULL};
    char buf[100];
    int ret;

    ret = capture_cmd_output(cmd, buf, sizeof(buf));

    printf("got %d bytes", ret);
    printf ("\n%s\n", buf);

    exit(0);
}
#endif
