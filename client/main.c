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
#define UDP_SUPPORT 1
#define TCP_SUPPORT 1
#define UID_LENGTH 16

#define ACK_LOG 0
//the thread function
void *timer_handler(void *);
int net_sendmsg(char* msg);
void *UDPMulticast_handler(void * sock);


//TCP
int sock;
int listener_sock;
pthread_mutex_t mutex;
pthread_t sniffer_thread;
//UDP listener thread!!
pthread_t sniffer_listener_thread;
char message[MESSAGE_SIZE] , server_reply[MESSAGE_SIZE];
char input_msg[MESSAGE_SIZE];
int sending_flag=0;
char UID[UID_LENGTH];
char UPWD[64];
char mServer_ADDR[16]="127.0.0.1";
int mServer_port=TCP_SENDER_PORT;
int mServer_UDP_port=7891;
int connect_type=0;//0:TCP,1:UDP

//UDP
struct sockaddr_in server;

//create one thread for UDP muticast case lisener!!!
//using one command to be muticast message to other client

//client [IP][port][UID][PWD]
int main(int argc , char *argv[])
{
    
#if 1
    puts(argv[1]);
    puts(argv[2]);
    strcpy(mServer_ADDR, argv[1]);
    mServer_port=atoi(argv[2]);
    strcpy(UID, argv[3]);
    strcpy(UPWD, argv[4]);
    connect_type=atoi(argv[5]);
#endif
    
/////create thread for listening multicast message
    if( pthread_create( &sniffer_listener_thread , NULL ,  UDPMulticast_handler , NULL) < 0)
    {
        perror("could not create thread");
        return 1;
    }
    
#if UDP_SUPPORT
/////////////////////UDP client
    
    
    
#endif
    
////////////////////TCP client
#if TCP_SUPPORT
    if(connect_type)
    {
        int portNum, nBytes;
        char buffer[1024];
        socklen_t addr_size;
        struct ip_mreq mreq;
        u_int yes=1;
        
        /*Create UDP socket*/
        sock = socket(PF_INET, SOCK_DGRAM, 0);
        
        /*Configure settings in address struct*/
        server.sin_family = AF_INET;
        server.sin_port = htons(mServer_UDP_port);
        server.sin_addr.s_addr = inet_addr(mServer_ADDR);
        memset(server.sin_zero, '\0', sizeof server.sin_zero);
        
        /*Initialize size variable to be used later on*/
        addr_size = sizeof server;
    }else
    {
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
    }
    
    
    puts("Connected\n");
    
    sprintf(message, "Connect");
    net_sendmsg(message);
    
    struct timeval timeout;
    timeout.tv_sec = 1;//timeout for 1 sec
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    if( recv(sock , server_reply , MESSAGE_SIZE , 0) < 0)
    {
        puts("recv failed");
        return 1;
    }
    
    puts(server_reply);
    //sending login information
    
    memset(message,0,MESSAGE_SIZE);
    sprintf(message, "L%s,%s",UID,UPWD);
    
    net_sendmsg(message);
    
    //Receive a reply from the server
    if( recv(sock , server_reply , MESSAGE_SIZE , 0) < 0)
    {
        puts("recv failed");
        return 1;
    }
    puts(server_reply);
    
    if( pthread_create( &sniffer_thread , NULL ,  timer_handler , (void*) sock) < 0)
    {
        perror("could not create thread");
        return 1;
    }
    
    //keep communicating with server
    while(1)
    {
        char UImsg[MESSAGE_SIZE]={0};
        //printf("waiting for next 7secs\n");
        puts("1:unicast message");
        puts("2:Multicast message");
        scanf("%[^\n]",UImsg);//fix the space issue
        memset(input_msg,0,MESSAGE_SIZE);
        if(!strcmp(UImsg,"1"))
        {
            strcat(input_msg,"U");
            puts("please enter the ID you want to send");
            scanf("%s" , UImsg);
            strcat(input_msg,UImsg);
            strcat(input_msg,",");
            puts("please type the message:");
            scanf("%s" , UImsg);
            //strcat(input_msg,UImsg);
            sprintf(input_msg, "%s%s",input_msg,UImsg);
            puts(input_msg);
            sending_flag=1;
        }else if(!strcmp(UImsg,"2"))
        {
            strcat(input_msg,"M");
            puts("please type the message:");
            scanf("%s" , UImsg);
            puts(UImsg);
            //strcat(input_msg,UImsg);
            sprintf(input_msg, "%s%s",input_msg,UImsg);
            puts(input_msg);
            sending_flag=1;
        }else{
            continue;
        }
        puts("sending message");
        while(sending_flag)
            sleep(1);
        
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
    time_t timeUDPA;
    time_t timeUDPB;
    
    time(&timeUDPA);
    
    while(1)
    {
        if(!sending_ACK)
        {
            time(&timeB);
            seconds = difftime(timeB,timeA);
            if(seconds>=POOlING_TIME)
            {
#if ACK_LOG
                puts("sending time every 7secs\n");
#endif
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
#if ACK_LOG
            puts("waiting..");
#endif
            int rec=recv(sock , server_reply , MESSAGE_SIZE , 0);
            if(rec < 0)
                rec=recv(sock , server_reply , MESSAGE_SIZE , 0);
            //Receive a reply from the server
            if(rec < 0)
            {
              //no ACK back timeout
              //counting the retry time
              puts("server no ack feedback");
              ACK_counter++;
              if(ACK_counter==5)
              {
                  puts("server no ack feedback 5 times!!");
                  break;
              }
            }else
            {
#if ACK_LOG
                puts("Server reply :");
                puts(server_reply);
#endif
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
                net_sendmsg(input_msg);
                //Receive a reply from the server
                memset(server_reply, 0, MESSAGE_SIZE);
                if( recv(sock , server_reply , MESSAGE_SIZE , 0) < 0)
                {
                    puts("sending message error");
                }
                sending_flag=0;
#if ACK_LOG
                puts("Server reply :");
                puts(server_reply);
#endif
                memset(server_reply, 0, MESSAGE_SIZE);
            }
            //if not anyother reason for sending out message.
            //recieving message every sec
            if(connect_type)
            {
                //UDP case using pulling request!!
                
                time(&timeUDPB);
                int UDPseconds = difftime(timeUDPB,timeUDPA);
                
                if(UDPseconds>=2)
                {
                    time(&timeUDPA);
                    memset(server_reply, 0, MESSAGE_SIZE);
                    net_sendmsg("P");
                    if( recv(sock , server_reply , MESSAGE_SIZE , 0) > 0)
                    {
                        //receive something from server!!
                        //
                        if(strcmp(server_reply,"NONE"))
                        {
                            puts("unicast:");
                            puts(server_reply);
                        }
                    }
                }
                
            }else
            {
                if( recv(sock , server_reply , MESSAGE_SIZE , 0) > 0)
                {
                    //receive something from server!!
                    //
                    puts(server_reply);
                }
            }
        }
        
    }
    return 0;
}

int net_sendmsg(char* msg)
{
    if(connect_type)//UDP
    {
        char temp[MESSAGE_SIZE+UID_LENGTH+1]={0};
        sprintf(temp, "%s,%s",UID,msg);
        sendto(sock,temp,strlen(temp),0,(struct sockaddr *)&server,sizeof(server));
    }else//TCP
    {
        if( send(sock , msg , strlen(msg) , 0) < 0)
        {
            puts("Send failed");
            return 1;
        }
    }
    
    return 0;
}

//UDP Multicast-listener
#define HELLO_PORT 12345
#define HELLO_GROUP "225.0.0.37"
#define MSGBUFSIZE 256
void *UDPMulticast_handler(void * sock)
{
    struct sockaddr_in addr;
    int fd, nbytes,addrlen;
    struct ip_mreq mreq;
    char msgbuf[MSGBUFSIZE];
    
    u_int yes=1;            /*** MODIFICATION TO ORIGINAL */
    
    /* create what looks like an ordinary UDP socket */
    if ((fd=socket(AF_INET,SOCK_DGRAM,0)) < 0) {
        perror("socket");
        exit(1);
    }
    
    
    /**** MODIFICATION TO ORIGINAL */
    /* allow multiple sockets to use the same PORT number */
    if (setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)) < 0) {
        perror("Reusing ADDR failed");
        exit(1);
    }
    /*** END OF MODIFICATION TO ORIGINAL */
    
    /* set up destination address */
    memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=htonl(INADDR_ANY); /* N.B.: differs from sender */
    addr.sin_port=htons(HELLO_PORT);
    
    /* bind to receive address */
    if (bind(fd,(struct sockaddr *) &addr,sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }
    
    /* use setsockopt() to request that the kernel join a multicast group */
    mreq.imr_multiaddr.s_addr=inet_addr(HELLO_GROUP);
    mreq.imr_interface.s_addr=htonl(INADDR_ANY);
    if (setsockopt(fd,IPPROTO_IP,IP_ADD_MEMBERSHIP,&mreq,sizeof(mreq)) < 0) {
        perror("setsockopt");
        exit(1);
    }
    
    /* now just enter a read-print loop */
    while (1) {
        addrlen=sizeof(addr);
        if ((nbytes=recvfrom(fd,msgbuf,MSGBUFSIZE,0,
                             (struct sockaddr *) &addr,&addrlen)) < 0) {
            perror("recvfrom");
            exit(1);
        }
        puts("Multicast:");
        puts(msgbuf);
        //printf("Multicast:%s",msgbuf);
    }
    return 0;
}
