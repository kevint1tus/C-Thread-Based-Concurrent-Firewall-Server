#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <regex.h>

#define BUFFERLENGTH 1024
void processReq(const char *buffer, char *response, size_t response_size);
typedef struct queryNode
{
    char query[256];
    struct queryNode *next;
} queryNode;
typedef struct ruleNode
{
    char rule[256];
    queryNode *queries;
    struct ruleNode *next;
} ruleNode;
typedef struct reqNode
{
    char request[256];
    struct reqNode *next;
} reqNode;
// Global vars
ruleNode *rules_head = NULL;
reqNode *requests_head = NULL;
pthread_mutex_t rules_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t requests_mutex = PTHREAD_MUTEX_INITIALIZER;
void error(const char *msg)
{
    perror(msg);
    exit(1);
}
int writeResult(int sockfd, char *buffer, size_t bufsize)
{
    int n = write(sockfd, &bufsize, sizeof(size_t));
    if (n < 0)
        return -1;
    n = write(sockfd, buffer, bufsize);
    if (n != bufsize)
        return -1;
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
void *processClientRequest(void *args)
{
    int *newsockfd = (int *)args;
    char *buffer = readRes(*newsockfd);
    char response[BUFFERLENGTH * 4] = {0};
    if (buffer)
    {
        processReq(buffer, response, sizeof(response));
        writeResult(*newsockfd, response, strlen(response) + 1);
        free(buffer);
    }
    close(*newsockfd);
    free(newsockfd);
    pthread_exit(NULL);
}
// adds a req to the linked list
void addReq(const char *request)
{
    reqNode *new_node = (reqNode *)malloc(sizeof(reqNode));
    if (!new_node)
        error("ERROR allocating memory");
    strncpy(new_node->request, request, 255);
    new_node->request[255] = '\0';
    pthread_mutex_lock(&requests_mutex);
    new_node->next = requests_head;
    requests_head = new_node;
    pthread_mutex_unlock(&requests_mutex);
}
// ------------------------------------------------
// Validation Checks
int isValidIp(const char *ip)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
}
int isValidPort(int port)
{
    return port >= 0 && port <= 65535;
}
int isValidIpRange(const char *ip_range)
{
    char start_ip[16], end_ip[16];
    struct in_addr start, end;
    if (sscanf(ip_range, " %15[0-9.] - %15[0-9.] ", start_ip, end_ip) == 2)
    {
        if (inet_aton(start_ip, &start) && inet_aton(end_ip, &end))
        {
            return ntohl(start.s_addr) <= ntohl(end.s_addr);
        }
    }
    else if (isValidIp(ip_range))
    {
        return 1; // Handles a single IP
    }
    return 0;
}
int isValidPortRange(const char *port_range)
{
    int start_port, end_port;
    if (strchr(port_range, '-'))
    {
        if (sscanf(port_range, "%d-%d", &start_port, &end_port) == 2 &&
            start_port >= 0 && end_port >= start_port && end_port <= 65535)
        {
            return 1;
        }
    }
    else
    {
        int port = atoi(port_range);
        return port >= 0 && port <= 65535;
    }
    return 0;
}
// --------------------------------------------------
void addQuery(ruleNode *rule, const char *ip, int port)
{
    queryNode *new_query = (queryNode *)malloc(sizeof(queryNode));
    if (!new_query)
        error("ERROR allocating memory");
    snprintf(new_query->query, sizeof(new_query->query), "%s %d", ip, port);
    new_query->next = rule->queries;
    rule->queries = new_query;
}
void freeQuery(queryNode *head)
{
    while (head != NULL)
    {
        queryNode *temp = head;
        head = head->next;
        free(temp);
    }
}
void deleteRule(const char *rule_str, char *response, size_t response_size)
{
    pthread_mutex_lock(&rules_mutex);
    ruleNode *current = rules_head;
    ruleNode *prev = NULL;
    int rule_deleted = 0;
    while (current != NULL)
    {
        if (strcmp(current->rule, rule_str) == 0)
        {
            if (prev == NULL)
            {
                rules_head = current->next;
            }
            else
            {
                prev->next = current->next;
            }
            freeQuery(current->queries);
            free(current);
            rule_deleted = 1;
            break;
        }
        prev = current;
        current = current->next;
    }
    if (rule_deleted)
    {
        snprintf(response, response_size, "Rule deleted\n");
    }
    else
    {
        snprintf(response, response_size, "Rule invalid\n");
    }
    pthread_mutex_unlock(&rules_mutex);
}
void processReq(const char *buffer, char *response, size_t response_size)
{
    char command[BUFFERLENGTH];
    char args[BUFFERLENGTH];
    sscanf(buffer, "%s %[^\n]", command, args);
    addReq(buffer);
    response[0] = '\0';
    if (strcmp(command, "R") == 0)
    {
        pthread_mutex_lock(&requests_mutex);
        reqNode *stack_head = NULL;
        // Traverse the requests list and push items onto the stack
        reqNode *req = requests_head;
        while (req != NULL)
        {
            reqNode *new_node = malloc(sizeof(reqNode));
            if (!new_node)
            {
                error("ERROR allocating memory");
            }
            strncpy(new_node->request, req->request, 255);
            new_node->request[255] = '\0';
            new_node->next = stack_head;
            stack_head = new_node;
            req = req->next;
        }
        // Now traverse the stack to print requests in reverse order
        reqNode *stack_req = stack_head;
        int first = 1;
        while (stack_req != NULL)
        {
            if (!first)
                strncat(response, "\n", response_size - strlen(response) - 1);
            snprintf(response + strlen(response), response_size - strlen(response),
                     "Request: %s", stack_req->request);
            reqNode *temp = stack_req;
            stack_req = stack_req->next;
            free(temp);
            first = 0;
        }
        pthread_mutex_unlock(&requests_mutex);
    }
    else if (strcmp(command, "A") == 0)
    {
        char ip_range[256], port_range[256];
        if (sscanf(args, "%255s %255s", ip_range, port_range) != 2 ||
            !isValidIpRange(ip_range) || !isValidPortRange(port_range))
        {
            snprintf(response, response_size, "Invalid rule");
            return;
        }
        ruleNode *new_rule = (ruleNode *)malloc(sizeof(ruleNode));
        if (!new_rule)
        {
            snprintf(response, response_size, "Error allocating memory\n");
            return;
        }
        strncpy(new_rule->rule, args, 255);
        new_rule->rule[255] = '\0';
        new_rule->queries = NULL;
        pthread_mutex_lock(&rules_mutex);
        new_rule->next = rules_head;
        rules_head = new_rule;
        pthread_mutex_unlock(&rules_mutex);
        snprintf(response, response_size, "Rule added");
    }
    else if (strcmp(command, "C") == 0)
    {
        char ip[16];
        char port_str[256];
        int port;
        if (sscanf(args, "%15s %255s", ip, port_str) != 2 || !isValidIp(ip) || !isValidPortRange(port_str))
        {
            snprintf(response, response_size, "Illegal IP address or port specified\
n");
            return;
        }
        port = atoi(port_str);
        pthread_mutex_lock(&rules_mutex);
        ruleNode *rule = rules_head;
        int matched = 0;
        while (rule != NULL && !matched)
        {
            char ip_range[256], port_range[256];
            int start_port, end_port;
            if (sscanf(rule->rule, "%s %s", ip_range, port_range) == 2 &&
                isValidIpRange(ip_range) &&
                ((strchr(port_range, '-') && sscanf(port_range, "%d-%d", &start_port, &end_port) == 2 && port >= start_port && port <= end_port) ||
                 (!strchr(port_range, '-') && atoi(port_range) == port)))
            {
                addQuery(rule, ip, port);
                matched = 1;
            }
            rule = rule->next;
        }
        pthread_mutex_unlock(&rules_mutex);
        snprintf(response, response_size, matched ? "Connection accepted\n" : "Connection rejected\n");
    }
    else if (strcmp(command, "D") == 0)
    {
        deleteRule(args, response, response_size);
    }
    else if (strcmp(command, "L") == 0)
    {
        pthread_mutex_lock(&rules_mutex);
        ruleNode *rule = rules_head;
        int first = 1;
        while (rule != NULL)
        {
            if (!first)
                strncat(response, "\n", response_size - strlen(response) - 1);
            snprintf(response + strlen(response), response_size - strlen(response),
                     "Rule: %s", rule->rule);
            queryNode *query = rule->queries;
            while (query != NULL)
            {
                snprintf(response + strlen(response), response_size - strlen(response),
                         "\nQuery: %s", query->query);
                query = query->next;
            }
            rule = rule->next;
            first = 0;
        }
        pthread_mutex_unlock(&rules_mutex);
    }
    else
    {
        snprintf(response, response_size, "Illegal request\n");
    }
}
void clear()
{
    ruleNode *rule = rules_head;
    while (rule != NULL)
    {
        ruleNode *next_rule = rule->next;
        freeQuery(rule->queries);
        free(rule);
        rule = next_rule;
    }
    reqNode *req = requests_head;
    while (req != NULL)
    {
        reqNode *next_req = req->next;
        free(req);
        req = next_req;
    }
    pthread_mutex_destroy(&rules_mutex);
    pthread_mutex_destroy(&requests_mutex);
}
void intMode()
{
    char buffer[BUFFERLENGTH];
    char response[BUFFERLENGTH * 4];
    while (1)
    {
        if (fgets(buffer, BUFFERLENGTH, stdin) == NULL)
            break;
        buffer[strcspn(buffer, "\n")] = 0;
        memset(response, 0, sizeof(response));
        processReq(buffer, response, sizeof(response));
        printf("%s\n", response);
    }
}
int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s [-i | port]\n", *argv);
        exit(1);
    }
    atexit(clear);
    if (strcmp(argv[1], "-i") == 0)
    {
        intMode();
        return 0;
    }
    int sockfd, portno;
    socklen_t clilen;
    struct sockaddr_in6 serv_addr, cli_addr;
    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");
    bzero((char *)&serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons(portno);
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);
    while (1)
    {
        int *newsockfd = malloc(sizeof(int));
        if (!newsockfd)
        {
            fprintf(stderr, "Memory allocation failed!\n");
            exit(1);
        }
        *newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (*newsockfd < 0)
        {
            free(newsockfd);
            error("ERROR on accept");
        }
        pthread_t server_thread;
        pthread_attr_t pthread_attr;
        if (pthread_attr_init(&pthread_attr) != 0 ||
            pthread_attr_setdetachstate(&pthread_attr, PTHREAD_CREATE_DETACHED) !=
                0 ||
            pthread_create(&server_thread, &pthread_attr, processClientRequest,
                           (void *)newsockfd) != 0)
        {
            free(newsockfd);
            error("ERROR creating thread");
        }
    }
    close(sockfd);
    return 0;
}
