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



//the thread function
void *timer_handler(void *);
int net_sendmsg(char* msg);
int sock;
pthread_mutex_t mutex;
pthread_t sniffer_thread;
char message[1000] , server_reply[2000];
char input_msg[1000];
int sending_flag=0;

int main(int argc , char *argv[])
{
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
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
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
    
    
////////////////////TCP client
#if 0
    struct sockaddr_in server;
    
    
    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
    
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons( 8888 );
    
    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }
    
    puts("Connected\n");
    pthread_mutex_init(&mutex, NULL);

#if 1
    if( pthread_create( &sniffer_thread , NULL ,  timer_handler , (void*) sock) < 0)
    {
        perror("could not create thread");
        return 1;
    }
#endif
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
    while(1)
    {
        //
        //scanf("%s" , message);
        sleep_counter++;
        sleep(1);
        //Delay(7000);
        if(sleep_counter==7)
        {
            printf("sending time every 7secs\n");
            time_t rawtime;
            struct tm * timeinfo;
            
            time (&rawtime);
            timeinfo = localtime (&rawtime);
            strftime (message,2000,"A%x %X",timeinfo);
            
            net_sendmsg(message);
            
            //Receive a reply from the server
            if( recv(sock , server_reply , 2000 , 0) < 0)
            {
                puts("recv failed");
                break;
            }
            
            puts("Server reply :");
            puts(server_reply);
            memset(server_reply, 0, 2000);
            sleep_counter=0;
        }else
        {
            if(sending_flag)
            {
                //for sending user input message
                sending_flag=0;
                
                net_sendmsg(input_msg);
                
                //Receive a reply from the server
                if( recv(sock , server_reply , 2000 , 0) < 0)
                {
                    puts("recv failed");
                    break;
                }
                
                puts("Server reply :");
                puts(server_reply);
                memset(server_reply, 0, 2000);
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
