#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define XOR_KEY 7  

// DATA base
struct User {
    char username[50];
    char password[50];
    char level[20]; 
};

// users
struct User users[] = {
    {"ahmed", "123", "Entry"},
    {"hashim", "password", "Medium"},
    {"admin", "admin", "Admin"}
};

// function to encrypt/decrypt using XOR
void xor_encrypt_decrypt(char *data) {
    for (int i = 0; i < strlen(data); i++) {
        data[i] ^= XOR_KEY;
    }
}

// auth user
char* authenticate(char *credentials) {
    char *username = strtok(credentials, ":");
    char *password = strtok(NULL, ":");

    if (username == NULL || password == NULL) {
        return "Invalid Credentials Format";
    }

    // see stored users
    for (int i = 0; i < sizeof(users) / sizeof(users[0]); i++) {
        if (strcmp(username, users[i].username) == 0 && strcmp(password, users[i].password) == 0) {
            static char response[BUFFER_SIZE];
            sprintf(response, "Authentication Successful - Level: %s", users[i].level);
            return response;
        }
    }

    return "Invalid Username or Password";
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // define server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // bind the socket
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    while (1) {
        
        new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }

        
        read(new_socket, buffer, BUFFER_SIZE);
        xor_encrypt_decrypt(buffer);  

        printf("Received credentials: %s\n", buffer);

        
        char *auth_response = authenticate(buffer);

        
        xor_encrypt_decrypt(auth_response);
        send(new_socket, auth_response, strlen(auth_response), 0);

        
        close(new_socket);
    }

    return 0;
}
