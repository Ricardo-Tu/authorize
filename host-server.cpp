#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include "hardwareinfo.h"
#include "./headerfiles/crypto/rsa/scrsa.h"

#define BUFFER_SIZE 1024
enum MsgType
{
    GetMsgInfoRequest = 1,
    GetmsgInfoBack = 2,
    CheckRequest = 3,
    CheckBack = 4,
    OTHERS = 5,
};

#define CHECK_SUCCESS 0x11
#define CHECK_FAILED 0x22

#pragma push
#pragma pack(1)
typedef struct _stMsg_
{
    MsgType type;
    long checkflag;
    long buffer_length;
    char buffer[512];
} stMsg, *pstMsg;
#pragma pop

void *handle_client(void *arg)
{
    int client_socket = *((int *)arg);
    char RecvBuffer[BUFFER_SIZE] = {0};
    char message[1024] = {0};
    memset(RecvBuffer, 0, sizeof(RecvBuffer));

    ssize_t msg_len;
    while ((msg_len = recv(client_socket, &RecvBuffer, sizeof(RecvBuffer), 0)) > 0)
    {
        char RetBuffer[1024] = "send to guest";
        if (((pstMsg)RecvBuffer)->type == GetMsgInfoRequest)
        {
            DbgPrint(("Enter getinfo handle.\n"));
            DbgPrint(("Received client <%ld> bytes:[", msg_len));
            for (long i = 0; i < msg_len; i++)
                DbgPrint(("%c", RecvBuffer[i]));
            DbgPrint(("]\n"));
            std::string info = GetHardwareInfo();
            stMsg retMsg;
            memset(&retMsg, 0x00, sizeof(retMsg));
            retMsg.type = GetmsgInfoBack;
            // std::cout << "size:[" << info.size() << "] 2:[" << info.length() << "]" << std::endl;
            memcpy(retMsg.buffer, info.c_str(), info.length());
            retMsg.buffer_length = info.length();
            Dbgcout("info string: " << info.length() << " \n"
                    << hexToString(retMsg.buffer) << std::endl);
            msg_len = send(client_socket, &retMsg, sizeof(retMsg), 0);
            DbgPrint(("Send to guest <%ld> bytes:[", msg_len));
            for (long i = 0; i < msg_len; i++)
                DbgPrint(("%c", retMsg.buffer[i]));
            DbgPrint(("]\n"));
        }
        else if (((pstMsg)RecvBuffer)->type == CheckRequest)
        {
            DbgPrint(("Enter check handle.\n"));
            DbgPrint(("Received client <%ld> bytes: <%s>\n", msg_len, RecvBuffer));
            std::string info = GetHardwareInfo();
            stMsg retMsg;
            memset(&retMsg, 0x00, sizeof(retMsg));
            retMsg.type = CheckBack;
            retMsg.buffer_length = 0;
            std::string hashstr(((pstMsg)RecvBuffer)->buffer);
            Dbgcout("Authorze hashStr from client: \n"
                    << hexToString(((pstMsg)RecvBuffer)->buffer) << std::endl);
            retMsg.checkflag = CheckHardwareInfo(hashstr);
            DbgPrint(("flag:%d\n",retMsg.checkflag));
            msg_len = send(client_socket, &retMsg, sizeof(stMsg), 0);
            DbgPrint(("Send to guest <%ld> bytes: <%s>\n", msg_len, retMsg.buffer));
        }
        else
        {
            stMsg retMsg;
            char hello[256] = "Hello from server.Others type.\n";
            memset(&retMsg, 0x00, sizeof(retMsg));
            retMsg.type = OTHERS;
            retMsg.buffer_length = 0;
            memcpy(retMsg.buffer, hello, sizeof(hello));
            DbgPrint(("Received client %ld bytes: %s\n", msg_len, RecvBuffer));
            memcpy(RetBuffer, "else send to guest", strlen("else send to guest"));
            msg_len = send(client_socket, &retMsg, sizeof(stMsg), 0);
            DbgPrint(("Send to guest %ld bytes: %s\n", msg_len, RecvBuffer));
        }
    }
    DbgPrint(("Client disconnected\n"));
    close(client_socket);
    free(arg);
    pthread_exit(NULL);
}

int main()
{
    int server_fd, new_socket;
    struct sockaddr_vm address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    pthread_t tid;

    if ((server_fd = socket(AF_VSOCK, SOCK_STREAM, 0)) == 0)
    {
        DbgPrint(("socket failed"));
        exit(EXIT_FAILURE);
    }
    memset(&address, 0, sizeof(struct sockaddr_vm));
    address.svm_family = AF_VSOCK;
    address.svm_port = 9999;
    address.svm_cid = VMADDR_CID_ANY;

    if (bind(server_fd, (const struct sockaddr *)&address, sizeof(struct sockaddr_vm)) < 0)
    {
        DbgPrint(("bind failed"));
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 0) < 0)
    {
        DbgPrint(("listen failed"));
        exit(EXIT_FAILURE);
    }

    while (true)
    {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
        {
            DbgPrint(("accept failed"));
            exit(EXIT_FAILURE);
        }
        // Create a new thread to handle the client
        int *new_client_socket = (int *)malloc(sizeof(int));
        *new_client_socket = new_socket;

        if (pthread_create(&tid, NULL, handle_client, (void *)new_client_socket) != 0)
        {
            DbgPrint(("Error creating thread"));
            free(new_client_socket);
            close(new_socket);
        }

        // Detach the thread so its resources are automatically released upon exit
        pthread_detach(tid);
    }

    return 0;
}
