#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define BUFFERLENGTH 1024
/* displays error messages from system calls */
void error(char *msg)
{
    perror(msg);
    exit(1);
}
int writeResult(int sockfd, char *buffer, size_t bufsize)
{
    int n = write(sockfd, &bufsize, sizeof(size_t));
    if (n < 0)
    {
        perror("Error writing response size");
        return -1;
    }
    n = write(sockfd, buffer, bufsize);
    if (n != bufsize)
    {
        perror("Error writing response content");
        return -1;
    }
    return 0;
}
char *readRes(int sockfd)
{
    size_t bufsize;
    int res = read(sockfd, &bufsize, sizeof(size_t));
    if (res != sizeof(size_t))
        return NULL;
    char *buffer = malloc(bufsize + 1);
    if (buffer)
    {
        buffer[bufsize] = '\0';
        res = read(sockfd, buffer, bufsize);
        if (res != bufsize)
        {
            free(buffer);
            return NULL;
        }
    }
    return buffer;
}
int main(int argc, char **argv)
{
    if (argc < 4)
    {
        fprintf(stderr, "Usage: %s <serverHost> <serverPort> <command> [args...]\
n",
                argv[0]);
        exit(1);
    }
    int sockfd;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int res;
    /* Setting up hints for address info */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Stream socket */
    hints.ai_protocol = 0;           /* Any protocol */
    res = getaddrinfo(argv[1], argv[2], &hints, &result);
    if (res != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        exit(EXIT_FAILURE);
    }
    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1)
        {
            continue;
        }
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
        {
            break;
        }
        close(sockfd);
    }
    if (rp == NULL)
    {
        fprintf(stderr, "Could not connect\n");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(result); /* Frees the addr info struct */
    char buffer[BUFFERLENGTH];
    int pos = snprintf(buffer, BUFFERLENGTH, "%s", argv[3]); // Add command
    for (int i = 4; i < argc && pos < BUFFERLENGTH; i++)
    {
        pos += snprintf(buffer + pos, BUFFERLENGTH - pos, " %s", argv[i]);
    }
    if (writeResult(sockfd, buffer, strlen(buffer)) < 0)
    {
        error("ERROR writing to socket");
    }
    char *response = readRes(sockfd);
    if (response)
    {
        printf("%s\n", response);
        free(response);
    }
    else
    {
        printf("No response from server.\n");
    }
    close(sockfd);
    return 0;
}
