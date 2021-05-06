//
// Copyright (C) 2020 MemVerge Inc.
//
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>

#define BUF_SIZE 4096
#define PORT_NUM 5678

int RestoreNormalMode(pid_t pid, char **resp_buf);
int EnterSafeMode(pid_t pid, char **resp_buf);
