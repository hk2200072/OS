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
    CryptoContext crypto;
} ClientInfo;

// Global variables
int server_fd;
ClientInfo *clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to authenticate user and return their access level
int authenticate_user(const char* username, const char* password, AccessLevel* level) {
    for (size_t i = 0; i < sizeof(users) / sizeof(users[0]); i++) {
        if (strcmp(users[i].username, username) == 0) {
            if (verify_password(password, users[i].password_hash)) {
                *level = users[i].level;
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

// Handle client commands
void handle_client_command(ClientInfo* client, const char* command, char* response) {
    char cmd[16], arg1[BUFFER_SIZE], arg2[BUFFER_SIZE];
    memset(cmd, 0, sizeof(cmd));
    memset(arg1, 0, sizeof(arg1));
    memset(arg2, 0, sizeof(arg2));
    
    // Extract command and arguments
    int args = sscanf(command, "%15s %1023s %1023s", cmd, arg1, arg2);
    
    // Log the received command (only if it's not LIST which is too frequent)
    if (strncmp(cmd, "LIST", 4) != 0) {
        printf("[%s] User '%s' sent command: '%s'\n", 
               get_current_time(), 
               client->authenticated ? client->username : "unauthenticated", 
               command);
    }
    
    if (args < 1) {
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
        // Handle LOGIN command
        if (strncmp(command, "LOGIN ", 6) == 0) {
            char username[32], password[64];
            if (sscanf(command + 6, "%31s %63s", username, password) == 2) {
                if (client->authenticated) {
                    strcpy(response, "Already logged in");
                } else {
                    AccessLevel level;
                    if (authenticate_user(username, password, &level)) {
                        // Initialize encryption
                        if (!init_crypto(&client->crypto)) {
                            strcpy(response, "Failed to initialize encryption");
                        } else {
                            client->authenticated = 1;
                            client->level = level;
                            strncpy(client->username, username, sizeof(client->username)-1);
                            sprintf(response, "Logged in successfully as %s", username);
                            printf("[%s] User '%s' logged in with level %d\n", 
                                  get_current_time(), username, level);
                            
                            // Add a special marker to separate login response from keys
                            char login_response[BUFFER_SIZE];
                            snprintf(login_response, sizeof(login_response), "%s\n<KEY_MARKER>", response);
                            send(client->socket, login_response, strlen(login_response), 0);
                            
                            // Send encryption keys after the marker
                            if (send(client->socket, client->crypto.key, KEY_SIZE, 0) != KEY_SIZE ||
                                send(client->socket, client->crypto.iv, IV_SIZE, 0) != IV_SIZE) {
                                printf("Failed to send encryption keys to client\n");
                            } else {
                                printf("Encryption keys sent to client\n");
                            }
                            
                            return; // Skip the normal response sending
                        }
                    } else {
                        strcpy(response, "Invalid username or password");
                    }
                }
            } else {
                strcpy(response, "Usage: LOGIN <username> <password>");
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
            send(client->socket, response, strlen(response), 0);
            
            // Send file size
            send(client->socket, &filesize, sizeof(filesize), 0);
            
            // Send file data
            send(client->socket, filedata, filesize, 0);
            
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
        
        // Receive file size
        size_t filesize;
        recv(client->socket, &filesize, sizeof(filesize), 0);
        
        // Receive file data
        char* filedata = malloc(filesize);
        size_t received = 0;
        while (received < filesize) {
            ssize_t n = recv(client->socket, filedata + received, filesize - received, 0);
            if (n <= 0) break;
            received += n;
        }
        
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

// Function declaration
void* handle_client(void* arg);

// Handle client connection
void* handle_client(void* arg) {
    ClientInfo* client = (ClientInfo*)arg;
    char command[BUFFER_SIZE], response[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE], decrypted[BUFFER_SIZE];
    
    // Create uploads directory if it doesn't exist
    mkdir(UPLOAD_DIR, 0755);
    mkdir("uploads/hash1", 0755);
    mkdir("uploads/hash2", 0755);
    mkdir("uploads/hash3", 0755);

    while (1) {
        // Clear buffers for each new command
        memset(command, 0, BUFFER_SIZE);
        memset(response, 0, BUFFER_SIZE);
        
        // Receive command
        if (client->authenticated) {
            // Receive encrypted length
            uint32_t encrypted_len;
            if (recv(client->socket, &encrypted_len, sizeof(encrypted_len), 0) != sizeof(encrypted_len)) {
                break;
            }
            encrypted_len = ntohl(encrypted_len);
            
            // Receive encrypted data
            if (recv(client->socket, encrypted, encrypted_len, 0) != encrypted_len) {
                break;
            }
            
            // Initialize decryption for this operation
            if (!EVP_DecryptInit_ex(client->crypto.ctx, EVP_aes_256_cbc(), NULL, 
                                   client->crypto.key, client->crypto.iv)) {
                break;
            }
            
            // Decrypt received command
            int decrypted_len;
            if (!decrypt_data(&client->crypto, encrypted, encrypted_len, decrypted, &decrypted_len)) {
                break;
            }
            decrypted[decrypted_len] = '\0';
            strncpy(command, (char*)decrypted, BUFFER_SIZE-1);
        } else {
            // Before authentication, handle command as plaintext
            ssize_t received = recv(client->socket, command, BUFFER_SIZE-1, 0);
            if (received <= 0) {
                break;
            }
            command[received] = '\0';
        }
        
        // Process the command and get response
        handle_client_command(client, command, response);
        
        // Send response
        if (client->authenticated) {
            // Initialize encryption for this operation
            if (!EVP_EncryptInit_ex(client->crypto.ctx, EVP_aes_256_cbc(), NULL, 
                                   client->crypto.key, client->crypto.iv)) {
                break;
            }
            
            // Encrypt response
            int encrypted_len;
            if (!encrypt_data(&client->crypto, (unsigned char*)response, strlen(response), 
                            encrypted, &encrypted_len)) {
                break;
            }
            
            // Send encrypted length first
            uint32_t len_network = htonl(encrypted_len);
            if (send(client->socket, &len_network, sizeof(len_network), 0) < 0) {
                break;
            }
            
            // Send encrypted data
            if (send(client->socket, encrypted, encrypted_len, 0) < 0) {
                break;
            }
        } else {
            if (send(client->socket, response, strlen(response), 0) < 0) {
                break;
            }
        }
    }
    
    if (client->authenticated && client->crypto.ctx) {
        EVP_CIPHER_CTX_free(client->crypto.ctx);
    }
    
    if (client->authenticated) {
        printf("[%s] User '%s' disconnected\n", get_current_time(), client->username);
    }
    
    close(client->socket);
    free(client);
    return NULL;
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
