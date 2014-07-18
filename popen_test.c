/* test the function of command line integrate into C*/
#include<sys/types.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>

int main(int argc, char* argv[])
{
  FILE *stream;
  char buf[1024];
  int tcpnum;
  bzero(buf, sizeof(buf));
  stream = popen("netstat -nat | wc -l", "r");
  fread( buf, sizeof(char), sizeof(buf), stream);
  tcpnum = atoi(buf);
  printf("nima %d \n", tcpnum);

  pclose(stream);
  return 0;
}
