#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 4443
#define MAX_CLIENTS 10
#define BUFFER_SIZE 4096

MYSQL *conn;

int validate_user(const char *username, const char *password) {
    char query[512];
    snprintf(query, sizeof(query),
             "SELECT * FROM users WHERE username='%s' AND password_hash='%s'",
             username, password);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "MySQL query failed: %s\n", mysql_error(conn));
        return 0;
    }

    MYSQL_RES *result = mysql_store_result(conn);
    int valid = (mysql_num_rows(result) > 0);
    mysql_free_result(result);
    return valid;
}

int register_user(const char *username, const char *password) {
    char query[512];
    snprintf(query, sizeof(query),
             "INSERT INTO users (username, password_hash, role) VALUES ('%s', '%s', 'user')",
             username, password);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "MySQL insert failed: %s\n", mysql_error(conn));
        return 0;
    }

    return 1;
}

void handle_client(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int bytes;

    // --- LOGIN or REGISTER ---
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        printf("[-] Login/Registration message read failed.\n");
        SSL_free(ssl);
        return;
    }
    buffer[bytes] = '\0';

    char command[16], username[100], password[100];
    sscanf(buffer, "%s %s %s", command, username, password);

    if (strcmp(command, "LOGIN") == 0) {
        if (!validate_user(username, password)) {
            SSL_write(ssl, "LOGIN_FAILED\n", strlen("LOGIN_FAILED\n"));
            SSL_free(ssl);
            return;
        }
        printf("[+] User '%s' logged in.\n", username);
        SSL_write(ssl, "LOGIN_SUCCESS\n", strlen("LOGIN_SUCCESS\n"));
    } else if (strcmp(command, "REGISTER") == 0) {
        if (!register_user(username, password)) {
            SSL_write(ssl, "REGISTER_FAILED\n", strlen("REGISTER_FAILED\n"));
            SSL_free(ssl);
            return;
        }
        printf("[+] New user '%s' registered.\n", username);
        SSL_write(ssl, "REGISTER_SUCCESS\n", strlen("REGISTER_SUCCESS\n"));
    } else {
        SSL_write(ssl, "UNKNOWN_COMMAND\n", strlen("UNKNOWN_COMMAND\n"));
        SSL_free(ssl);
        return;
    }

    // --- COMMAND LOOP ---
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            printf("[-] Failed to read command or client disconnected.\n");
            break;
        }
        buffer[bytes] = '\0';

        if (strncmp(buffer, "UPLOAD", 6) == 0) {
            // Receive filename
            bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes <= 0) break;
            buffer[bytes] = '\0';

            char filename[100];
            strncpy(filename, buffer, sizeof(filename) - 1);

            char path[200];
            snprintf(path, sizeof(path), "uploads/%s_%s.enc", username, filename);
            FILE *fp = fopen(path, "wb");
            if (!fp) {
                perror("File open failed");
                break;
            }

            while (1) {
                bytes = SSL_read(ssl, buffer, sizeof(buffer));
                if (bytes <= 0) break;
                if (bytes == 3 && strncmp(buffer, "EOF", 3) == 0) break;
                fwrite(buffer, 1, bytes, fp);
            }

            fclose(fp);
            SSL_write(ssl, "UPLOAD_SUCCESS\n", strlen("UPLOAD_SUCCESS\n"));
            printf("[+] File '%s' uploaded by user '%s'.\n", filename, username);
        } else {
            printf("[-] Unknown command: %s\n", buffer);
        }
    }

    SSL_free(ssl);
}

void *client_thread(void *arg) {
    SSL *ssl = (SSL *)arg;
    handle_client(ssl);
    return NULL;
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (!SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[-] Socket creation failed");
        SSL_CTX_free(ctx);
        return 1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[-] Bind failed");
        close(server_fd);
        SSL_CTX_free(ctx);
        return 1;
    }

    listen(server_fd, MAX_CLIENTS);
    printf("[+] Server listening on port %d...\n", PORT);

    conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, "localhost", "root", "lavanya", "secure_transfer", 0, NULL, 0)) {
        fprintf(stderr, "[-] MySQL connection failed: %s\n", mysql_error(conn));
        close(server_fd);
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("[+] Connected to MySQL successfully.\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &len);
        if (client_fd < 0) {
            perror("[-] Accept failed");
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, ssl) != 0) {
            perror("[-] pthread_create failed");
            SSL_free(ssl);
        } else {
            pthread_detach(tid);
        }
    }

    close(server_fd);
    mysql_close(conn);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
