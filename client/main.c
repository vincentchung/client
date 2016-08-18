/*
 C ECHO client example using sockets
 */
#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include<pthread.h> //for threading , link with lpthread
#define TCP_SENDER_PORT 8888
#define MESSAGE_SIZE 256
#define POOlING_TIME 7
#define UDP_SUPPORT 0
#define TCP_SUPPORT 1


//the thread function
void *timer_handler(void *);
int net_sendmsg(char* msg);
int sock;
int listener_sock;
pthread_mutex_t mutex;
pthread_t sniffer_thread;
pthread_t sniffer_listener_thread;
char message[MESSAGE_SIZE] , server_reply[MESSAGE_SIZE];
char input_msg[MESSAGE_SIZE];
int sending_flag=0;
char UID[64];
char UPWD[64];
char mServer_ADDR[16]="127.0.0.1";
int mServer_port=TCP_SENDER_PORT;

//client [IP][port][UID][PWD]
int main(int argc , char *argv[])
{
    puts("\n");
    puts(argv[1]);
    puts(argv[2]);
    strcpy(UID, argv[3]);
    strcpy(UPWD, argv[4]);
#if UDP_SUPPORT
/////////////////////UDP client
    
    int clientSocket, portNum, nBytes;
    char buffer[1024];
    struct sockaddr_in serverAddr;
    socklen_t addr_size;
    
    /*Create UDP socket*/
    clientSocket = socket(PF_INET, SOCK_DGRAM, 0);
    
    /*Configure settings in address struct*/
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(7891);
    serverAddr.sin_addr.s_addr = inet_addr(mServer_ADDR);
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
    
    /*Initialize size variable to be used later on*/
    addr_size = sizeof serverAddr;
    
    while(1){
        printf("Type a sentence to send to server:\n");
        fgets(buffer,1024,stdin);
        printf("You typed: %s",buffer);
        
        nBytes = strlen(buffer) + 1;
        
        /*Send message to server*/
        sendto(clientSocket,buffer,nBytes,0,(struct sockaddr *)&serverAddr,addr_size);
        
        /*Receive message from server*/
        nBytes = recvfrom(clientSocket,buffer,1024,0,NULL, NULL);
        
        printf("Received from server: %s\n",buffer);
        
    }
#endif
    
////////////////////TCP client
#if TCP_SUPPORT
    struct sockaddr_in server;
    struct sockaddr_in listener_server;
    
    
    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
    
    server.sin_addr.s_addr = inet_addr(mServer_ADDR);
    server.sin_family = AF_INET;
    server.sin_port = htons( mServer_port );
    
    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }
    
    puts("Connected\n");
    
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    if( recv(sock , server_reply , MESSAGE_SIZE , 0) < 0)
    {
        puts("recv failed");
        return 1;
    }
    
    puts(server_reply);
    //sending login information
    
    sprintf(message, "L%s,%s",UID,UPWD);
    
    net_sendmsg(message);
    
    //Receive a reply from the server
    if( recv(sock , server_reply , MESSAGE_SIZE , 0) < 0)
    {
        puts("recv failed");
        return 1;
    }
    puts(server_reply);
    
    pthread_mutex_init(&mutex, NULL);

    if( pthread_create( &sniffer_thread , NULL ,  timer_handler , (void*) sock) < 0)
    {
        perror("could not create thread");
        return 1;
    }
    
    //keep communicating with server
    while(1)
    {
        //printf("waiting for next 7secs\n");
        scanf("%s" , input_msg);
        sending_flag=1;
    }
    
    close(sock);
#endif
    return 0;
}

void *timer_handler(void * sock)
{
    int sleep_counter=0;
    int ACK_counter=0;
    time_t timeA;
    time_t timeB;
    struct tm newyear;
    double seconds;
    time(&timeA);  /* get current time; same as: now = time(NULL)  */
    int sending_ACK=0;
    
    
    while(1)
    {
        if(!sending_ACK)
        {
            time(&timeB);
            seconds = difftime(timeB,timeA);
            if(seconds>=POOlING_TIME)
            {
                puts("sending time every 7secs\n");
                sending_ACK=1;
            }
        }
        
        if(sending_ACK)
        {
            //formating the time string
            time_t rawtime;
            struct tm * timeinfo;
            
            time (&rawtime);
            timeinfo = localtime (&rawtime);
            strftime (message,MESSAGE_SIZE,"A%x %X",timeinfo);
            
            net_sendmsg(message);
            puts("waiting..\n");
            //Receive a reply from the server
            if( recv(sock , server_reply , MESSAGE_SIZE , 0) < 0)
            {
                //no ACK back timeout
                //counting the retry time
                puts("recv failed");
                ACK_counter++;
                if(ACK_counter==5)
                    break;
            }else
            {
                puts("Server reply :");
                puts(server_reply);
                memset(server_reply, 0, MESSAGE_SIZE);
                time(&timeA);
                ACK_counter=0;
                sending_ACK=0;
            }
        }else
        {
            if(sending_flag)
            {
                //for sending user input message
                sending_flag=0;
                
                net_sendmsg(input_msg);
                
                //Receive a reply from the server
                if( recv(sock , server_reply , MESSAGE_SIZE , 0) < 0)
                {
                    puts("recv failed");
                    break;
                }
                
                puts("Server reply :");
                puts(server_reply);
                memset(server_reply, 0, MESSAGE_SIZE);
            }
            //if not anyother reason for sending out message.
            //recieving message every sec
            if( recv(sock , server_reply , MESSAGE_SIZE , 0) < 0)
            {
                //timeout
            }
        }
        
    }
    return 0;
}

int net_sendmsg(char* msg)
{
    if( send(sock , msg , strlen(msg) , 0) < 0)
    {
        puts("Send failed");
        return 1;
    }
    return 0;
}
