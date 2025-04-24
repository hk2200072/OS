#include "common.h"
#include "security.h"
#include "ftp.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#define MAX_CLIENTS 10
#define UPLOAD_DIR "uploads"

// Get current time as string
char* get_current_time() {
    static char buffer[26];
    time_t timer;
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    return buffer;
}

typedef struct {
    int socket;
    struct sockaddr_in address;
    AccessLevel level;
    char username[32];
    int authenticated;
    SecurityContext security_ctx; // Security context for encryption/decryption
} ClientInfo;

// Global variables
int server_fd;
ClientInfo *clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to authenticate user and return their access level
int authenticate_user(const char* username, const char* password, AccessLevel* level) {
    for (int i = 0; i < sizeof(AUTHORIZED_USERS) / sizeof(AUTHORIZED_USERS[0]); i++) {
        if (strcmp(username, AUTHORIZED_USERS[i].username) == 0 &&
            verify_sha256_password(password, AUTHORIZED_USERS[i].password_hash)) {
            *level = AUTHORIZED_USERS[i].level;
            return 1;
        }
    }
    return 0;
}

// Handle client commands
void handle_client_command(ClientInfo* client, const char* command, char* response) {
    char cmd[32], arg1[256], arg2[BUFFER_SIZE];
    arg1[0] = arg2[0] = '\0';
    memset(response, 0, BUFFER_SIZE);

    // First get the command
    if (sscanf(command, "%31s", cmd) != 1) {
        strcpy(response, "Invalid command format");
        return;
    }

    // Get the rest of the line after the command
    const char* rest = command + strlen(cmd);
    while (*rest == ' ') rest++; // Skip spaces

    if (strcmp(cmd, "WRITE") == 0) {
        // Get filename
        char* space = strchr(rest, ' ');
        if (!space || space == rest) {
            strcpy(response, "Usage: WRITE <filename> <content>");
            return;
        }
        
        // Copy filename
        size_t fname_len = space - rest;
        if (fname_len >= sizeof(arg1)) {
            strcpy(response, "Filename too long");
            return;
        }
        strncpy(arg1, rest, fname_len);
        arg1[fname_len] = '\0';
        
        // Get content (skip spaces after filename)
        const char* content = space + 1;
        while (*content == ' ') content++;
        
        if (*content == '\0') {
            strcpy(response, "No content provided");
            return;
        }
        
        strncpy(arg2, content, BUFFER_SIZE - 1);
        arg2[BUFFER_SIZE - 1] = '\0';
    } else {
        // Normal command parsing
        sscanf(rest, "%255s %s", arg1, arg2);
    }

    if (!client->authenticated) {
        if (strcmp(cmd, "LOGIN") == 0) {
            char username[32], password[32];
            if (sscanf(command, "LOGIN %s %s", username, password) == 2) {
                if (authenticate_user(username, password, &client->level)) {
                    client->authenticated = 1;
                    strncpy(client->username, username, sizeof(client->username)-1);
                    client->level = client->level;
                    strcpy(response, "Logged in successfully");
                    sprintf(response + strlen(response), " as %s", username);
                    printf("[%s] User '%s' logged in with %s access level\n", 
                           get_current_time(), username, 
                           client->level == TOP_LEVEL ? "TOP" : 
                           client->level == MEDIUM_LEVEL ? "MEDIUM" : "ENTRY");
                } else {
                    strcpy(response, "Invalid credentials");
                }
            }
        } else {
            strcpy(response, "Please login first");
        }
        return;
    }

    // Handle authenticated commands
    if (strcmp(cmd, "LIST") == 0) {
        // Create uploads directory and hash-level directories if they don't exist
        mkdir(UPLOAD_DIR, 0755);
        char hash_dir[512];
        snprintf(hash_dir, sizeof(hash_dir), "%s/hash1", UPLOAD_DIR);
        mkdir(hash_dir, 0755);
        snprintf(hash_dir, sizeof(hash_dir), "%s/hash2", UPLOAD_DIR);
        mkdir(hash_dir, 0755);
        snprintf(hash_dir, sizeof(hash_dir), "%s/hash3", UPLOAD_DIR);
        mkdir(hash_dir, 0755);
        int result = handle_list_directory(client->level, UPLOAD_DIR, response);
        if (result != FTP_SUCCESS || strlen(response) == 0) {
            strcpy(response, "Directory is empty");
        }
    }
    else if (strcmp(cmd, "DOWNLOAD") == 0) {
        char filepath[512];
        // Check if path contains hash directory, if not, use the user's hash level
        if (strstr(arg1, "hash") == NULL) {
            const char* hash_level = client->level == TOP_LEVEL ? "hash3" :
                                    client->level == MEDIUM_LEVEL ? "hash2" : "hash1";
            snprintf(filepath, sizeof(filepath), "%s/%s/%s", UPLOAD_DIR, hash_level, arg1);
        } else {
            snprintf(filepath, sizeof(filepath), "%s/%s", UPLOAD_DIR, arg1);
        }
        
        // Read file and send it
        struct stat st;
        if (stat(filepath, &st) != 0) {
            strcpy(response, "File not found");
            return;
        }
        size_t filesize = st.st_size;
        char* filedata = malloc(filesize);
        
        int result = handle_download_file(client->level, filepath, filedata, &filesize);
        if (result == FTP_SUCCESS) {
            strcpy(response, "Download starting");
            
            // Encrypt the response
            unsigned char encrypted_resp[BUFFER_SIZE];
            int resp_len = strlen(response);
            xor_encrypt_decrypt(&client->security_ctx, (unsigned char*)response, resp_len, encrypted_resp);
            send(client->socket, encrypted_resp, resp_len, 0);
            
            // Encrypt and send file size
            unsigned char encrypted_size[sizeof(filesize)];
            xor_encrypt_decrypt(&client->security_ctx, (unsigned char*)&filesize, sizeof(filesize), encrypted_size);
            send(client->socket, encrypted_size, sizeof(filesize), 0);
            
            // Encrypt and send file data
            unsigned char* encrypted_data = malloc(filesize);
            xor_encrypt_decrypt(&client->security_ctx, (unsigned char*)filedata, filesize, encrypted_data);
            send(client->socket, encrypted_data, filesize, 0);
            free(encrypted_data);
            
            printf("[%s] User '%s' downloaded file: %s\n", get_current_time(), client->username, arg1);
        } else {
            strcpy(response, "Download failed");
        }
        
        free(filedata);
        return;
    }
    else if (strcmp(cmd, "UPLOAD") == 0) {
        char filepath[512];
        // Check if path contains hash directory, if not, use the user's hash level
        if (strstr(arg1, "hash") == NULL) {
            const char* hash_level = client->level == TOP_LEVEL ? "hash3" :
                                    client->level == MEDIUM_LEVEL ? "hash2" : "hash1";
            snprintf(filepath, sizeof(filepath), "%s/%s/%s", UPLOAD_DIR, hash_level, arg1);
        } else {
            snprintf(filepath, sizeof(filepath), "%s/%s", UPLOAD_DIR, arg1);
        }
        
        // Receive encrypted file size
        size_t filesize;
        unsigned char encrypted_size[sizeof(filesize)];
        recv(client->socket, encrypted_size, sizeof(filesize), 0);
        
        // Decrypt file size
        xor_encrypt_decrypt(&client->security_ctx, encrypted_size, sizeof(filesize), (unsigned char*)&filesize);
        
        // Receive encrypted file data
        unsigned char* encrypted_data = malloc(filesize);
        char* filedata = malloc(filesize);
        size_t received = 0;
        while (received < filesize) {
            ssize_t n = recv(client->socket, encrypted_data + received, filesize - received, 0);
            if (n <= 0) break;
            received += n;
        }
        
        // Decrypt file data if fully received
        if (received == filesize) {
            xor_encrypt_decrypt(&client->security_ctx, encrypted_data, filesize, (unsigned char*)filedata);
        }
        
        free(encrypted_data);
        
        if (received == filesize) {
            int result = handle_upload_file(client->level, filepath, filedata, filesize);
            if (result == FTP_SUCCESS) {
                printf("[%s] User '%s' uploaded file: %s\n", get_current_time(), client->username, arg1);
                strcpy(response, "Upload successful");
            } else {
                strcpy(response, "Upload failed");
            }
        } else {
            strcpy(response, "File transfer failed");
        }
        
        free(filedata);
    }
    else if (strcmp(cmd, "DOWNLOAD") == 0) {
        char filepath[512];
        // Check if path contains hash directory, if not, use the user's hash level
        if (strstr(arg1, "hash") == NULL) {
            const char* hash_level = client->level == TOP_LEVEL ? "hash3" :
                                    client->level == MEDIUM_LEVEL ? "hash2" : "hash1";
            snprintf(filepath, sizeof(filepath), "%s/%s/%s", UPLOAD_DIR, hash_level, arg1);
        } else {
            snprintf(filepath, sizeof(filepath), "%s/%s", UPLOAD_DIR, arg1);
        }
        
        char* filedata = malloc(BUFFER_SIZE);
        size_t filesize;
        
        int result = handle_download_file(client->level, filepath, filedata, &filesize);
        if (result == FTP_SUCCESS) {
            // Send file size
            send(client->socket, &filesize, sizeof(filesize), 0);
            // Send file data
            send(client->socket, filedata, filesize, 0);
            strcpy(response, "File sent successfully");
        } else {
            strcpy(response, "Download failed");
        }
        
        free(filedata);
    }
    else if (strcmp(cmd, "DELETE") == 0) {
        char filepath[512];
        // Check if path contains hash directory, if not, use the user's hash level
        if (strstr(arg1, "hash") == NULL) {
            const char* hash_level = client->level == TOP_LEVEL ? "hash3" :
                                    client->level == MEDIUM_LEVEL ? "hash2" : "hash1";
            snprintf(filepath, sizeof(filepath), "%s/%s/%s", UPLOAD_DIR, hash_level, arg1);
        } else {
            snprintf(filepath, sizeof(filepath), "%s/%s", UPLOAD_DIR, arg1);
        }
        
        int result = handle_delete_file(client->level, filepath);
        if (result == FTP_SUCCESS) {
            printf("[%s] User '%s' deleted file: %s\n", get_current_time(), client->username, arg1);
            strcpy(response, "File deleted successfully");
        } else {
            strcpy(response, "Delete failed");
        }
    }
    else if (strcmp(cmd, "COPY") == 0) {
        char src[512], dst[512], dir[512];
        
        // Handle source path
        if (strstr(arg1, "hash") == NULL) {
            // Source is in root directory
            snprintf(src, sizeof(src), "%s/%s", UPLOAD_DIR, arg1);
        } else {
            snprintf(src, sizeof(src), "%s/%s", UPLOAD_DIR, arg1);
        }
        
        // Handle destination path
        if (strstr(arg2, "hash") == NULL) {
            // If no hash specified, use user's level
            const char* hash_level = client->level == TOP_LEVEL ? "hash3" :
                                    client->level == MEDIUM_LEVEL ? "hash2" : "hash1";
            snprintf(dst, sizeof(dst), "%s/%s/%s", UPLOAD_DIR, hash_level, arg2);
            // Create hash directory if it doesn't exist
            snprintf(dir, sizeof(dir), "%s/%s", UPLOAD_DIR, hash_level);
            mkdir(dir, 0755);
        } else {
            // Extract directory path from destination
            snprintf(dst, sizeof(dst), "%s/%s", UPLOAD_DIR, arg2);
            char* last_slash = strrchr(dst, '/');
            if (last_slash) {
                strncpy(dir, dst, last_slash - dst);
                dir[last_slash - dst] = '\0';
                mkdir(dir, 0755);
            }
        }
        
        int result = handle_copy_file(client->level, src, dst);
        if (result == FTP_SUCCESS) {
            printf("[%s] User '%s' copied file: %s to %s\n", get_current_time(), client->username, arg1, arg2);
            strcpy(response, "File copied successfully");
        } else {
            strcpy(response, "Copy failed");
        }
    }
    else if (strcmp(cmd, "MOVE") == 0) {
        char src[512], dst[512], dir[512];
        
        // Handle source path
        if (strstr(arg1, "hash") == NULL) {
            // Source is in root directory
            snprintf(src, sizeof(src), "%s/%s", UPLOAD_DIR, arg1);
        } else {
            snprintf(src, sizeof(src), "%s/%s", UPLOAD_DIR, arg1);
        }
        
        // Handle destination path
        if (strstr(arg2, "hash") == NULL) {
            // If no hash specified, use user's level
            const char* hash_level = client->level == TOP_LEVEL ? "hash3" :
                                    client->level == MEDIUM_LEVEL ? "hash2" : "hash1";
            snprintf(dst, sizeof(dst), "%s/%s/%s", UPLOAD_DIR, hash_level, arg2);
            // Create hash directory if it doesn't exist
            snprintf(dir, sizeof(dir), "%s/%s", UPLOAD_DIR, hash_level);
            mkdir(dir, 0755);
        } else {
            // Extract directory path from destination
            snprintf(dst, sizeof(dst), "%s/%s", UPLOAD_DIR, arg2);
            char* last_slash = strrchr(dst, '/');
            if (last_slash) {
                strncpy(dir, dst, last_slash - dst);
                dir[last_slash - dst] = '\0';
                mkdir(dir, 0755);
            }
        }
        
        int result = handle_move_file(client->level, src, dst);
        if (result == FTP_SUCCESS) {
            printf("[%s] User '%s' moved file: %s to %s\n", get_current_time(), client->username, arg1, arg2);
            strcpy(response, "File moved successfully");
        } else {
            strcpy(response, "Move failed");
        }
    }
    else if (strcmp(cmd, "READ") == 0) {
        char filepath[512];
        // Check if path contains hash directory, if not, use the user's hash level
        if (strstr(arg1, "hash") == NULL) {
            const char* hash_level = client->level == TOP_LEVEL ? "hash3" :
                                    client->level == MEDIUM_LEVEL ? "hash2" : "hash1";
            snprintf(filepath, sizeof(filepath), "%s/%s/%s", UPLOAD_DIR, hash_level, arg1);
        } else {
            snprintf(filepath, sizeof(filepath), "%s/%s", UPLOAD_DIR, arg1);
        }
        
        char content[BUFFER_SIZE];
        int result = handle_read_file(client->level, filepath, content, BUFFER_SIZE);
        if (result == FTP_SUCCESS) {
            snprintf(response, BUFFER_SIZE, "File contents:\n%s", content);
        } else {
            strcpy(response, "Cannot read file");
        }
    }
    else if (strcmp(cmd, "WRITE") == 0) {
        if (strlen(arg2) == 0) {
            strcpy(response, "Usage: WRITE <filename> <content>");
            return;
        }
        
        char filepath[512];
        // Check if path contains hash directory, if not, use the user's hash level
        if (strstr(arg1, "hash") == NULL) {
            const char* hash_level = client->level == TOP_LEVEL ? "hash3" :
                                    client->level == MEDIUM_LEVEL ? "hash2" : "hash1";
            snprintf(filepath, sizeof(filepath), "%s/%s/%s", UPLOAD_DIR, hash_level, arg1);
        } else {
            snprintf(filepath, sizeof(filepath), "%s/%s", UPLOAD_DIR, arg1);
        }
        
        int result = handle_write_file(client->level, filepath, arg2);
        if (result == FTP_SUCCESS) {
            printf("[%s] User '%s' wrote to file: %s\n", get_current_time(), client->username, arg1);
            strcpy(response, "File written successfully");
        } else {
            strcpy(response, "Write failed");
        }
    }
    else {
        strcpy(response, "Unknown command");
    }
}

// Handle client connection
void* handle_client(void* arg) {
    ClientInfo* client = (ClientInfo*)arg;
    char buffer[BUFFER_SIZE], response[BUFFER_SIZE];
    unsigned char encrypted_buffer[BUFFER_SIZE], encrypted_response[BUFFER_SIZE];
    
    // Create uploads directory if it doesn't exist
    mkdir(UPLOAD_DIR, 0755);
    
    // First, receive the encryption key from client
    recv(client->socket, client->security_ctx.key, KEY_SIZE, 0);
    printf("Received encryption key from client\n");

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        memset(encrypted_buffer, 0, BUFFER_SIZE);
        
        // Receive encrypted data
        int bytes_received = recv(client->socket, encrypted_buffer, BUFFER_SIZE-1, 0);
        
        if (bytes_received <= 0) {
            break;
        }
        
        // Decrypt the received data
        xor_encrypt_decrypt(&client->security_ctx, encrypted_buffer, bytes_received, (unsigned char*)buffer);
        
        // Process the command
        handle_client_command(client, buffer, response);
        
        // Encrypt the response
        int response_len = strlen(response);
        xor_encrypt_decrypt(&client->security_ctx, (unsigned char*)response, response_len, encrypted_response);
        
        // Send encrypted response
        send(client->socket, encrypted_response, response_len, 0);
    }

    if (client->authenticated) {
        printf("[%s] User '%s' disconnected\n", get_current_time(), client->username);
    }
    close(client->socket);
    free(client);
    pthread_exit(NULL);
}

int main() {
    struct sockaddr_in address;
    int opt = 1;

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("FTP Server started on port %d\n", PORT);
    printf("Waiting for connections...\n");

    while (1) {
        ClientInfo* client = malloc(sizeof(ClientInfo));
        socklen_t addrlen = sizeof(client->address);

        client->socket = accept(server_fd, (struct sockaddr *)&client->address, &addrlen);
        if (client->socket < 0) {
            free(client);
            continue;
        }

        client->authenticated = 0;
        client->level = ENTRY_LEVEL;

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, (void*)client) != 0) {
            perror("Could not create thread");
            close(client->socket);
            free(client);
            continue;
        }

        pthread_detach(thread_id);
    }

    return 0;
}
