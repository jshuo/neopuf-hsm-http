
// gcc -o p256_http_server p256_http_server.c -I$(brew --prefix openssl)/include -L$(brew --prefix openssl)/lib -lssl -lcrypto
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#define PORT 8081  // Changed port number

void error(const char *msg) {
    perror(msg);
    exit(1);
}

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

EC_KEY *generate_key() {
    EC_KEY *key = NULL;
    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL)
        handle_errors();
    if (EC_KEY_generate_key(key) != 1)
        handle_errors();
    return key;
}

void key_to_hex(EC_KEY *key, char *buffer, size_t len) {
    const BIGNUM *priv_key = EC_KEY_get0_private_key(key);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);

    char *priv_hex = BN_bn2hex(priv_key);
    char *pub_hex = EC_POINT_point2hex(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL);

    snprintf(buffer, len, "Private Key: %s\nPublic Key: %s\n", priv_hex, pub_hex);

    OPENSSL_free(priv_hex);
    OPENSSL_free(pub_hex);
}

void handle_request(int newsockfd) {
    char buffer[256];
    int n;

    bzero(buffer, 256);
    n = read(newsockfd, buffer, 255);
    if (n < 0) error("ERROR reading from socket");

    printf("Request: %s\n", buffer);

    // Generate the P-256 key
    EC_KEY *key = generate_key();

    // Convert the key to hex format
    char key_str[4096];
    key_to_hex(key, key_str, sizeof(key_str));

    // Prepare and send the response
    char response[8192];
    snprintf(response, sizeof(response), 
             "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n%s", key_str);
    n = write(newsockfd, response, strlen(response));
    if (n < 0) error("ERROR writing to socket");

    EC_KEY_free(key);
    close(newsockfd);
}

int main(int argc, char *argv[]) {
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;

    // Initialize OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error("ERROR opening socket");

    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = PORT;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR on binding");

    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    while (1) {
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) error("ERROR on accept");

        handle_request(newsockfd);
    }

    close(sockfd);

    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
