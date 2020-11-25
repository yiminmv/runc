//
// Copyright (C) 2020 MemVerge Inc.
//
#include "nsops.go.h"

#define DEBUG_LOG 1

#define LOG(fmt, ...)                                        \
  if (DEBUG_LOG) {                                           \
    fprintf(stderr, fmt, ##__VA_ARGS__);                     \
  }

static const char *kSafeMode = "safe_mode";
static const char *kNormalMode = "normal";
static const char *kSnapshot = "snapshot";

#define ACT_SNAPSHOT 1
#define ACT_NORMALMODE 2

static struct namespace_file {
  int nstype;
  const char *name;
  int fd;
} ns_files[] = {
  { .nstype = CLONE_NEWIPC,   .name = "ns/ipc",  .fd = -1 },
  { .nstype = CLONE_NEWUTS,   .name = "ns/uts",  .fd = -1 },
  { .nstype = CLONE_NEWNET,   .name = "ns/net",  .fd = -1 },
  { .nstype = CLONE_NEWPID,   .name = "ns/pid",  .fd = -1 },
  { .nstype = CLONE_NEWNS,    .name = "ns/mnt",  .fd = -1 },
  { .nstype = 0, .name = NULL, .fd = -1 }
};

static inline void errExit(const char *msg) {
  fprintf(stderr, "[process %ld] exit: %s, errno: %d, msg: %s\n",
                    (long) getpid(), msg, errno, strerror(errno));
  exit(1);
}

struct node {
  int val;
  struct node* next;
};

struct queue {
  struct node *front, *tail;
};

struct node* new_node(int val) {
  struct node* cur = (struct node*) malloc(sizeof(struct node));
  cur->val = val;
  cur->next = NULL;
  return cur;
}

struct queue* new_queue() {
  struct queue *que = (struct queue*) malloc(sizeof(struct queue));
  que->front = que->tail = NULL;
  return que;
}

void queue_push(struct queue *que, int val) {
  struct node *cur = new_node(val);

  if (que->tail == NULL) {
    que->front = que->tail = cur;
    return;
  }

  que->tail->next = cur;
  que->tail = cur;
}

void queue_pop(struct queue *que, int *val) {
  if (que->front == NULL)
    return;

  struct node *cur = que->front;
  que->front = que->front->next;
  *val = cur->val;

  if (que->front == NULL)
    que->tail = NULL;

  free(cur);
}

char* readfile(const char* filepath) {
  char *buf = (char *)malloc(BUF_SIZE);
  memset(buf, 0, BUF_SIZE);
  int fd;

  fd = open(filepath, O_RDONLY);
  if (fd == -1)
    errExit("readfile-open");

  if (read(fd, buf, BUF_SIZE) < 0)
    errExit("readfile-read");

  close(fd);
  return buf;
}

char* get_pstree(pid_t pid) {
  char *pid_buf = malloc(BUF_SIZE);
  if (pid_buf == NULL)
    errExit("malloc");

  memset(pid_buf, 0, BUF_SIZE);
  struct queue *que = new_queue();
  queue_push(que, pid);

  while (que->front != NULL) {
    pid_t cur;
    char path_buf[PATH_MAX];
    char pid_str[10];

    queue_pop(que, &cur);
    /* append current pid to pud_buf */
    snprintf(pid_str, 10, "%d,", cur);
    strcat(pid_buf, pid_str);

    snprintf(path_buf, PATH_MAX, "/proc/%d/task", cur);
    DIR* dir = opendir(path_buf);
    if (dir == NULL)
      errExit("opendir");

    /* open the subdirectories under /proc/$pid/task */
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
      if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
        continue;

      snprintf(path_buf, PATH_MAX, "/proc/%d/task/%s/children",
                cur, entry->d_name);
      char *buf = readfile(path_buf);
      if (buf == NULL || strlen(buf) == 0)
        continue;

      /* tokenlize the pids read from the file */
      char *tok = buf;
      int pid_val = strtol(tok, &tok, 10);
      while (pid_val != 0) {
        queue_push(que, pid_val);
        pid_val = strtol(tok, &tok, 10);
      }
      free(buf);
    }
  }
  /* remove the last comma */
  pid_buf[strlen(pid_buf) - 1] = '\0';
  return pid_buf;
}

char* broadcast(const char* cmd) {
  struct sockaddr_in svaddr;
  int sfd;
  size_t msgLen;
  size_t numBytes;
  char *resp;
  int yes = 1, ret;

  resp = (char *) malloc(PATH_MAX);
  if (resp == NULL)
    errExit("malloc");

  sfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sfd == -1)
    errExit("socket");

  ret = setsockopt(sfd, SOL_SOCKET, SO_BROADCAST, (char*)&yes, sizeof(yes));
  if (ret == -1)
    errExit("setsockopt");

  memset(&svaddr, 0, sizeof(struct sockaddr_in));
  svaddr.sin_family = AF_INET;
  svaddr.sin_port = htons(PORT_NUM);
  inet_pton(AF_INET, "127.255.255.255", &svaddr.sin_addr);

  msgLen = strlen(cmd);
  if (sendto(sfd, cmd, msgLen, 0, (struct sockaddr *) &svaddr,
              sizeof(struct sockaddr_in)) != msgLen)
    errExit("sendto");

  numBytes = recvfrom(sfd, resp, BUF_SIZE, 0, NULL, NULL);
  if (numBytes == -1)
    errExit("recvfrom");

  LOG("Response: %.*s\n", (int) numBytes, resp);
  return resp;
}

void join_namespace(pid_t pid) {
  char pathbuf[PATH_MAX];
  struct namespace_file *nsfile;

  memset(pathbuf, 0, PATH_MAX);
  for (nsfile = ns_files; nsfile->nstype; nsfile++) {
    snprintf(pathbuf, PATH_MAX, "/proc/%d/%s", pid, nsfile->name);
    LOG("opening %s\n", pathbuf);

    nsfile->fd = open(pathbuf, O_RDONLY);
    if (nsfile->fd < 0)
      errExit("open ns");

    LOG("join namespace: %s\n", nsfile->name);
    if (setns(nsfile->fd, nsfile->nstype) == -1)
      errExit("setns");
    close(nsfile->fd);
    nsfile->fd = -1;
  }
}

int nsenter(int *pip, pid_t pid, int action) {
  struct stat st;
  char *resp;
  char req[BUF_SIZE];
  memset(req, 0, BUF_SIZE);

  int child = fork();
  /* if it's parent or an error, return */
  if (child != 0)
    return child;

  /* CHILD PROCESS
   * namespace operations will be limited in this process, after
   * it sends back the message to parent, the child will exit.
   * the namespaces we joined depends what we want to do in this
   * namespace, if we want to access /proc/, joining the /ns/mnt is
   * sufficient.
   */
  join_namespace(pid);

  if (stat("/proc/1/ns/pid", &st))
    errExit("stat");

  char *pids =  get_pstree(1);
  switch (action) {
  case ACT_SNAPSHOT:
    snprintf(req, BUF_SIZE, "ns=%ju:pids=%s:cmd=%s",
            (uintmax_t) st.st_ino, pids, kSafeMode);
    LOG("Sending cmd: %s\n", req);
    resp = broadcast(req);

    snprintf(req, BUF_SIZE, "ns=%ju:pids=%s:cmd=%s",
            (uintmax_t) st.st_ino, pids, kSnapshot);
    LOG("Sending cmd: %s\n", req);
    broadcast(req);
    break;
  case ACT_NORMALMODE:
    snprintf(req, BUF_SIZE, "ns=%ju:pids=%s:cmd=%s",
            (uintmax_t) st.st_ino, pids, kNormalMode);
    LOG("Sending cmd: %s\n", req);
    resp = broadcast(req);
    break;

  default:
    errExit("action");
  }

  /* write back the response message */
  LOG("child [%ld] write: %s\n", (long) getpid(), resp);
  if (write(pip[1], resp, PATH_MAX) < 0)
    errExit("write");

  free(pids);
  free(resp);
  exit(0);
}

int exec_action(pid_t pid, char **resp_buf, int action) {
  int pip[2];
  fd_set readfds;
  struct timeval timeout;

  if (pipe(pip) == -1)
    errExit("pipe");

  *resp_buf = malloc(PATH_MAX);
  if (*resp_buf == NULL)
    errExit("malloc");
  memset(*resp_buf, 0, PATH_MAX);

  if (nsenter(pip, pid, action) < 0)
    errExit("nsenter");

  /* use select() to wait for the message back from the child
    * in case for child's failure, add a 5 second timeout
    */
  close(pip[1]);
  FD_ZERO(&readfds);
  FD_SET(pip[0], &readfds);
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;

  if (select(FD_SETSIZE, &readfds, NULL, NULL, &timeout) < 0)
    errExit("select");

  if (read(pip[0], *resp_buf, PATH_MAX) < 0)
    errExit("read");

  /* almost done, later the go runtime will take over */
  LOG("parent [%ld] read: %s\n", (long) getpid(), *resp_buf);

  close(pip[0]);
  return 0;
}

int RestoreNormalMode(pid_t pid, char **resp_buf) {
  return exec_action(pid, resp_buf, ACT_NORMALMODE);
}

int EnterSafeMode(pid_t pid, char **resp_buf) {
  return exec_action(pid, resp_buf, ACT_SNAPSHOT);
}
