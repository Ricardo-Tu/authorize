#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <iostream>
#include <bitset>
#include <string>
#include <sstream>
#include <iomanip>
#include "./headerfiles/crypto/rsa/scrsa.h"
#include "authorize.h"

#define BUFFER_SIZE 1024
enum MsgType
{
        GetMsgInfoRequest = 1,
        GetmsgInfoBack = 2,
        CheckRequest = 3,
        CheckBack = 4,
        OTHERS = 5,
};

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

int main()
{
        int sock = socket(AF_VSOCK, SOCK_STREAM, 0);
        struct sockaddr_vm addr;
        stMsg stSendMsg;
        char RecvBuffer[BUFFER_SIZE];

        memset(&addr, 0, sizeof(struct sockaddr_vm));
        addr.svm_family = AF_VSOCK;
        addr.svm_port = 9999;
        addr.svm_cid = VMADDR_CID_HOST;

        if (connect(sock, (const struct sockaddr *)&addr, sizeof(struct sockaddr_vm)) < 0)
        {
                printf("connect failed!\n");
        }

        // send GetHardwareInfo request
        DbgPrint(("\nSend GetHardwareInfo request.\n"));
        memset(&stSendMsg, 0x00, sizeof(stMsg));
        stSendMsg.type = GetMsgInfoRequest;

        ssize_t msg_len = send(sock, &stSendMsg, sizeof(stMsg), 0);
        if (msg_len <= 0)
        {
                printf("Send failed.\n");
                exit(EXIT_FAILURE);
        }
        printf("GetHardwareInfo message send to server %d bytes.\n", msg_len);

        memset(&RecvBuffer, 0x00, sizeof(RecvBuffer));
        msg_len = recv(sock, &RecvBuffer, sizeof(RecvBuffer), 0);
        if (msg_len <= 0)
        {
                perror("client recvmsg failed\n");
                exit(EXIT_FAILURE);
        }
        printf("gethardwareinfo Respose %d bytes from server: type <%d>  flag<%d> buffer:\n[",
               msg_len,
               ((pstMsg)RecvBuffer)->type,
               ((pstMsg)RecvBuffer)->checkflag);
        for (long i = 0; i < ((pstMsg)RecvBuffer)->buffer_length; i++)
                printf("%c", ((pstMsg)RecvBuffer)->buffer[i]);
        printf("]\n");

        std::string buf(((pstMsg)RecvBuffer)->buffer);
        DbgPrint(("check string that to send : %d",buf.length()));
        std::string output = hexCharStrToString(((pstMsg)RecvBuffer)->buffer, ((pstMsg)RecvBuffer)->buffer_length);
        printf("std::string:\n[");
        for (long i = 0; i < output.length(); i++)
                printf("%c", output.c_str()[i]);
        printf("]\n");
        DbgPrint(("==================================================\n"));

        // send error Check request
        DbgPrint(("\nSend error check request.\n"));
        stSendMsg.type = CheckRequest;
        stSendMsg.buffer_length = 0;
        char HardwareStr[512] = "1234";
        memcpy(stSendMsg.buffer, HardwareStr, sizeof(HardwareStr));
        msg_len = send(sock, &stSendMsg, sizeof(stMsg), 0);
        if (msg_len <= 0)
        {
                printf("Send failed 2.\n");
                exit(EXIT_FAILURE);
        }
        msg_len = recv(sock, &RecvBuffer, sizeof(RecvBuffer), 0);
        if (msg_len <= 0)
        {
                printf("Recv failed. 2\n");
                exit(EXIT_FAILURE);
        }
        printf("send error check std::string:\n[");
        for (long i = 0; i < ((pstMsg)RecvBuffer)->buffer_length; i++)
                printf("%c", ((pstMsg)RecvBuffer)->buffer[i]);
        printf("]\n");
        printf("Error check flag Response from server:<%d>\n", ((pstMsg)RecvBuffer)->checkflag);
        DbgPrint(("==================================================\n"));

        // send right check request
        DbgPrint(("\nSend right check request.\n"));
        memset(&stSendMsg, 0x00, sizeof(stMsg));
        stSendMsg.type = CheckRequest;
        stSendMsg.buffer_length = buf.length();
        std::string phainString = authorizeString(buf);
        memcpy(stSendMsg.buffer, phainString.c_str(), phainString.length());
        msg_len = send(sock, &stSendMsg, sizeof(stMsg), 0);
        if (msg_len <= 0)
        {
                printf("Send failed 3.\n");
                exit(EXIT_FAILURE);
        }
        printf("send right check std::string:\n[");
        Dbgcout(hexToString(phainString));
        printf("]\n");
        DbgPrint(("buf:%[%d] phain:[%d]\n", buf.length(), phainString.length()));
        msg_len = recv(sock, &RecvBuffer, sizeof(RecvBuffer), 0);
        if (msg_len <= 0)
        {
                printf("Recv failed. 3\n");
                exit(EXIT_FAILURE);
        }
        printf("send right check recv std::string:\n[");
        for (long i = 0; i < ((pstMsg)RecvBuffer)->buffer_length; i++)
                printf("%c", ((pstMsg)RecvBuffer)->buffer[i]);
        printf("]\n");
        printf("Right check Response from server:<%d>\n", ((pstMsg)RecvBuffer)->checkflag);
        DbgPrint(("==================================================\n"));

        close(sock);

        return 0;
}
