#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define XOR_KEY 7  


void xor_encrypt_decrypt(char *data) {
    for (int i = 0; i < strlen(data); i++) {
        data[i] ^= XOR_KEY;
    }
}

int main() {
    int sock;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE] = {0};

    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Define server address
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY; //for local port 

    // connecting to the server
    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // get user creds
    char username[50], password[50], credentials[BUFFER_SIZE];

    printf("Enter username: ");
    scanf("%s", username);
    printf("Enter password: ");
    scanf("%s", password);

    // format credentials as "username:password"
    sprintf(credentials, "%s:%s", username, password);

    // encrypt credentials
    xor_encrypt_decrypt(credentials);

    // send encrypted credentials to the server
    send(sock, credentials, strlen(credentials), 0);

    // receive response from server
    read(sock, buffer, BUFFER_SIZE);

    // decrypt server message
    xor_encrypt_decrypt(buffer);
    printf("Server: %s\n", buffer);

    // closing the socket
    close(sock);

    return 0;
}
