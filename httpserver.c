// Bhatia, Ajay
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

#define OPTIONS              "t:l:"
#define DEFAULT_THREAD_COUNT 4

#define BUF_SIZE  2048
#define BUF_SIZE2 4096

#define LOG(...) fprintf(logfile, __VA_ARGS__);

// Regex Fields
#define METHOD  "([a-zA-Z]{1,8})"
#define URI     "(/[a-zA-Z0-9._]{1,19})"
#define VERSION "(HTTP/[0-9].[0-9])"
#define HEADER  "([a-zA-Z0-9]+: [a-zA-Z0-9]+\r\n)+"

// Regex Logs
#define REGNORM METHOD " " URI " " VERSION "\r\n"

#define CREATED 201
#define ERROR   500
#define NOIMP   501
#define BADREQ  400
#define NORMREQ 200

struct stat st;

extern int errno;
int status = 200;
char *message = "OK";
int len = 3;
char *body = "";
char *uri = "";
char *method = "";
int id = 0;
static FILE *logfile;

// RESPONSE FUNCTIONS --------------------------------------------------------
int write_get(int connfd, int fd) {
    char buffer[BUF_SIZE2];
    ssize_t bytez = 0;

    while ((bytez = read(fd, buffer, BUF_SIZE2)) > 0) {
        ssize_t bytez_written = 0, curr_write = 0;

        while (bytez_written < bytez) {
            curr_write = write(connfd, buffer + bytez_written, bytez - bytez_written);
            if (curr_write < 0) {
                return 0;
            }
            bytez_written += curr_write;
        }
    }

    return 0;
}

int send_response(int connfd) {
    int length = 0;
    char *buf = calloc(2048, sizeof(char));
    if (strcmp(method, "GET") == 0) {
        length = snprintf(
            NULL, 0, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n", status, message, len);
        buf = realloc(buf, length + 1);
        snprintf(
            buf, length + 1, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n", status, message, len);
    } else {
        length = snprintf(
            NULL, 0, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n%s", status, message, len, body);
        buf = realloc(buf, length + 1);
        snprintf(buf, length + 1, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n%s", status, message,
            len, body);
    }

    int bytez_written = 0;
    int nbytes = length;
    int bytez;

    while (bytez_written < nbytes) {

        bytez = write(connfd, buf + bytez_written, nbytes - bytez_written);

        if (bytez < 0) {

            return 1;
        }

        bytez_written += bytez;
    }

    free(buf);
    if (strcmp(method, "GET") == 0) {
        int fd = open(uri, O_RDONLY);
        write_get(connfd, fd);
        close(fd);
    }

    LOG("%s,/%s,%d,%d\n", method, uri, status, id);
    fflush(logfile);

    return 0;
}

void set_response(int errnum) {
    if (errnum == 129 || errnum == 2) {
        status = 404;
        message = "Not Found";
        body = "Not Found\n";
        len = strlen(body);
    } else if (errnum == 111 || errnum == 123) {
        status = 403;
        message = "Forbidden";
        body = "Forbidden\n";
        len = strlen(body) + 1;
    } else if (errnum == CREATED) {
        status = 201;
        message = "Created";
        body = "Created\n";
        len = strlen(body);
    } else if (errnum == ERROR) {
        status = 500;
        message = "Internal Server Error";
        body = "Internal Server Error\n";
        len = strlen(body);
    } else if (errnum == NOIMP) {
        status = 501;
        message = "Not Implemented";
        body = "Not Implemented\n";
        len = strlen(body);
    } else if (errnum == BADREQ) {
        status = 400;
        message = "Bad Request";
        body = "Bad Request\n";
        len = strlen(body);
    } else if (errnum == NORMREQ) {
        status = 200;
        message = "OK";
        body = "OK\n";
        len = strlen(body);
    }
}

// VALIDATE FUNCTIONS --------------------------------------------------------

int check_version(char *v) {
    if (strcmp(v, "HTTP/1.1") != 0) {
        set_response(BADREQ);
        return 1;
    }
    return 0;
}

int check_length(char *h) {
    char *ret;

    ret = strstr(h, "Content-Length:");
    if (!ret) {
        set_response(BADREQ);
        return 1;
    }
    return 0;
}

// PARSE FUNCTIONS --------------------------------------------------------

int find_length(char *h) {
    char str[strlen(h)];
    strncpy(str, h, strlen(h));
    char *token;
    char *key = "\r\n";
    token = strtok(str, key);
    char *ret;
    while (token != NULL) {
        if ((ret = strstr(token, "Content-Length: "))) {
            return atoi(ret + 16);
        }

        token = strtok(NULL, key);
    }

    return 0;
}

int find_request(char *h) {
    char str[strlen(h)];
    strncpy(str, h, strlen(h));
    char *token;
    char *key = "\r\n";
    token = strtok(str, key);
    char *ret;
    while (token != NULL) {
        if ((ret = strstr(token, "Request-Id: "))) {
            return atoi(ret + 12);
        }
        token = strtok(NULL, key);
    }
    return 0;
}

// GET FUNCTIONS --------------------------------------------------------
int validate_get(char *u) {
    int fd;
    fd = open(u, O_RDONLY);

    if (errno != 0) {
        set_response(errno);
        return 1;
    }

    close(fd);

    return 0;
}

int get_request(char *u) {
    if (validate_get(u) != 0) {
        return 1;
    }
    int fd;
    fd = open(u, O_RDONLY);

    fstat(fd, &st);
    int size = st.st_size;
    len = size;

    close(fd);

    return 0;
}

// FILE WRITE FUNCTIONS -------------------------------------------------

int write_file(int connfd, int fd, int length) {
    char buffer[BUF_SIZE2];
    ssize_t bytez = 0;
    int bytes_read = 0;
    while (bytes_read < length && (bytez = read(connfd, buffer, BUF_SIZE2)) > 0) {
        bytes_read += bytez;
        ssize_t bytez_written = 0, curr_write = 0;
        while (bytez_written < bytez) {
            curr_write = write(fd, buffer + bytez_written, bytez - bytez_written);
            if (curr_write < 0) {
                return 1;
            }
            bytez_written += curr_write;
        }
    }
    return 0;
}

// PUT FUNCTIONS --------------------------------------------------------
int validate_put(char *u, char *h) {
    if (check_length(h) != 0) {
        return 1;
    }

    int fd;
    fd = open(u, O_WRONLY | O_TRUNC, 0777);

    if (errno != 0) {
        if (errno != 2) {
            set_response(errno);
        }
        return errno;
    }

    close(fd);
    return 0;
}

int put_request(int connfd, char *u, char *h) {
    int val = 0;
    if ((val = validate_put(u, h)) == 2) {
        set_response(CREATED);
    } else if (val != 0) {
        return 1;
    }

    int fd;

    fd = open(u, O_WRONLY | O_CREAT | O_TRUNC, 0777);

    int length = find_length(h);

    write_file(connfd, fd, length);

    close(fd);

    return 0;
}

// APP FUNCTIONS --------------------------------------------------------

int validate_app(char *u, char *h) {
    if (check_length(h) != 0) {
        return 1;
    }

    int fd;
    fd = open(u, O_WRONLY | O_APPEND, 0777);

    if (errno != 0) {
        set_response(errno);
        return errno;
    }

    close(fd);
    return 0;
}

int app_request(int connfd, char *u, char *h) {
    if (validate_app(u, h) != 0) {
        return 1;
    }

    int fd;

    fd = open(u, O_WRONLY | O_APPEND, 0777);

    int length = find_length(h);

    write_file(connfd, fd, length);

    close(fd);

    return 0;
}

// PROCESS FUNCTIONS --------------------------------------------------------

int process_request(int connfd, char *m, char *u, char *v, char *h) {
    id = find_request(h);
    if (check_version(v) != 0) {
        return 1;
    }
    if (strcmp(m, "GET") == 0) {
        if (get_request(u) != 0) {
            return 1;
        }
    } else if (strcmp(m, "PUT") == 0) {
        if (put_request(connfd, u, h) != 0) {
            return 1;
        }
    } else if (strcmp(m, "APPEND") == 0) {
        if (app_request(connfd, u, h) != 0) {
            return 1;
        }
    } else {
        set_response(NOIMP);
        return 1;
    }
    return 0;
}

// PARSE FUNCTIONS --------------------------------------------------------

int parse_message(int connfd, char *request) {
    regex_t re;
    if (regcomp(&re, REGNORM, REG_EXTENDED) != 0) {
        set_response(BADREQ);
        return 1;
    }

    regmatch_t groups[4];
    if (regexec(&re, request, 4, groups, 0) != 0) {
        set_response(BADREQ);
        return 1;
    }

    // METHOD
    int start = groups[1].rm_so;
    int stop = groups[1].rm_eo;
    char m[stop - start + 1];
    strncpy(m, request + start, stop - start);
    m[stop - start] = '\0';
    method = realloc(method, stop - start + 1);
    strncpy(method, m, stop - start + 1);

    // URI
    start = groups[2].rm_so + 1;
    stop = groups[2].rm_eo;
    char u[stop - start + 1];
    strncpy(u, request + start, stop - start);
    u[stop - start] = '\0';
    uri = realloc(uri, stop - start + 1);
    strncpy(uri, u, stop - start + 1);

    // HTTP
    start = groups[3].rm_so;
    stop = groups[3].rm_eo;
    char v[stop - start + 1];
    strncpy(v, request + start, stop - start);
    v[stop - start] = '\0';

    // HEADERS
    start = groups[3].rm_eo;
    stop = strlen(request);
    char h[stop - start + 1];
    strncpy(h, request + start, stop - start);
    h[stop - start] = '\0';

    if (process_request(connfd, m, u, v, h) != 0) {
        regfree(&re);
        return 1;
    }
    regfree(&re);
    return 0;
}

// INPUT FUNCTIONS --------------------------------------------------------

int handle_connection(int connfd) {
    char buffer[BUF_SIZE];
    char *ret;
    ssize_t bytez = 0;
    char *request = calloc(2048, sizeof(char));
    int bytes_read = 0;

    while ((ret = strstr(request, "\r\n\r\n")) == NULL && (bytez = read(connfd, buffer, 1)) > 0) {
        strncat(request, buffer, 1);
    }
    int retu = parse_message(connfd, request);
    if (ret == NULL) {
        return 1;
    }

    send_response(connfd);

    if (retu != 0) {
        return retu;
    }
    while ((bytez = read(connfd, buffer + bytes_read, 1)) > 0) {
        bytes_read += bytez;
    }
    return 0;
}

// CONN FUNCTIONS --------------------------------------------------------

// Converts a string to an 16 bits unsigned integer.
// Returns 0 if the string is malformed or out of the range.
static size_t strtouint16(char number[]) {
    char *last;
    long num = strtol(number, &last, 10);
    if (num <= 0 || num > UINT16_MAX || *last != '\0') {
        return 0;
    }
    return num;
}

// Creates a socket for listening for connections.
// Closes the program and prints an error message on error.
static int create_listen_socket(uint16_t port) {
    struct sockaddr_in addr;
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        err(EXIT_FAILURE, "socket error");
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htons(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(listenfd, (struct sockaddr *) &addr, sizeof addr) < 0) {
        err(EXIT_FAILURE, "bind error");
    }
    if (listen(listenfd, 128) < 0) {
        err(EXIT_FAILURE, "listen error");
    }
    return listenfd;
}

static void sigterm_handler(int sig) {
    if (sig == SIGTERM) {
        warnx("received SIGTERM");
        fclose(logfile);
        exit(EXIT_SUCCESS);
    }
}

static void usage(char *exec) {
    fprintf(stderr, "usage: %s [-t threads] [-l logfile] <port>\n", exec);
}

int main(int argc, char *argv[]) {
    int opt = 0;
    int threads = DEFAULT_THREAD_COUNT;
    body = calloc(4, sizeof(char));
    strncpy(body, "OK\n", 4);
    uri = calloc(8, sizeof(char));
    strncpy(uri, "foo.txt", 8);
    method = calloc(4, sizeof(char));
    strncpy(method, "GET", 4);

    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 't':
            threads = strtol(optarg, NULL, 10);
            if (threads <= 0) {
                errx(EXIT_FAILURE, "bad number of threads");
            }
            break;
        case 'l':
            logfile = fopen(optarg, "w");
            if (!logfile) {
                errx(EXIT_FAILURE, "bad logfile");
            }
            break;
        default: usage(argv[0]); return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        free(body);
        free(uri);
        free(method);
        warnx("wrong number of arguments");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    uint16_t port = strtouint16(argv[optind]);
    if (port == 0) {
        free(body);
        free(uri);
        free(method);
        errx(EXIT_FAILURE, "bad port number: %s", argv[1]);
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, sigterm_handler);

    int listenfd = create_listen_socket(port);

    while (1) {
        int connfd = accept(listenfd, NULL, NULL);
        if (connfd < 0) {
            warn("accept error");
            continue;
        }
        handle_connection(connfd);
        errno = 0;
        set_response(NORMREQ);
        // good code opens and closes objects in the same context. *sigh*
        close(connfd);
    }

    free(body);
    free(uri);
    free(method);

    return EXIT_SUCCESS;
}
