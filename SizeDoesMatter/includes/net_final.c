#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#define RSA_KEY_BITS 1024
#define SERVER_COUNT 60  // Total number of servers
#define SPAM_COUNT 50    // Number of servers to send spam data

const char *server_N = "10.0.0.104";
const char *server_e = "198.51.100.22";
const char *server_c = "51.15.220.32";

const char* FLAG = "PCTF{Redacted}";  // The flag to be encrypted

// Function to send UDP packets
void send_udp_data(const char *server_ip, int port, const char *data) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

    sendto(sockfd, data, strlen(data), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    close(sockfd);
}

// RSA Key Generation & Encryption
void generate_rsa_and_send() {
    BIGNUM *p = BN_new(), *q = BN_new(), *N = BN_new();
    BIGNUM *phi = BN_new(), *e = BN_new(), *d = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    if (!p || !q || !N || !phi || !e || !d || !ctx) {
        printf("Failed to initialize OpenSSL components\n");
        exit(1);
    }

    // Generate two large prime numbers p and q
    BN_generate_prime_ex(p, RSA_KEY_BITS / 2, 1, NULL, NULL, NULL);
    BN_generate_prime_ex(q, RSA_KEY_BITS / 2, 1, NULL, NULL, NULL);

    // Compute N = p * q
    BN_mul(N, p, q, ctx);

    // Compute phi(N) = (p - 1) * (q - 1)
    BIGNUM *p_minus1 = BN_new(), *q_minus1 = BN_new();
    BN_sub(p_minus1, p, BN_value_one());
    BN_sub(q_minus1, q, BN_value_one());
    BN_mul(phi, p_minus1, q_minus1, ctx);

    // Compute N^0.25 / 3 (fourth root of N divided by 3)
    BIGNUM *N_fourth_root = BN_new(), *three = BN_new();
    BN_set_word(three, 3);
    int bits = BN_num_bits(N);
    BN_rshift(N_fourth_root, N, bits / 4);
    BN_div(N_fourth_root, NULL, N_fourth_root, three, ctx);

    // Generate small d in range [2, N^0.25/3]
    BIGNUM *two = BN_new();
    BN_set_word(two, 2);
    do {
        BN_rand_range(d, N_fourth_root);
    } while (BN_cmp(d, two) <= 0);

    // Compute e = d^-1 mod phi(N)
    if (!BN_mod_inverse(e, d, phi, ctx)) {
        printf("Failed to compute modular inverse for e\n");
        exit(1);
    }

    // Encrypt the flag
    BIGNUM *m = BN_new(), *c = BN_new();
    BN_bin2bn((unsigned char*)FLAG, strlen(FLAG), m);
    BN_mod_exp(c, m, e, N, ctx);

    // Convert BIGNUMs to strings
    char *N_str = BN_bn2dec(N);
    char *e_str = BN_bn2dec(e);
    char *c_str = BN_bn2dec(c);

    // Log the fixed destinations
    printf("[INFO] Sending N to %s\n", server_N);
    printf("[INFO] Sending e to %s\n", server_e);
    printf("[INFO] Sending c to %s\n", server_c);

    // Send N, e, c
    send_udp_data(server_N, 1337, N_str);
    send_udp_data(server_e, 1337, e_str);
    send_udp_data(server_c, 1337, c_str);

    OPENSSL_free(N_str);
    OPENSSL_free(e_str);
    OPENSSL_free(c_str);
    BN_free(p);
    BN_free(q);
    BN_free(N);
    BN_free(phi);
    BN_free(e);
    BN_free(d);
    BN_free(p_minus1);
    BN_free(q_minus1);
    BN_free(N_fourth_root);
    BN_free(three);
    BN_free(two);
    BN_free(m);
    BN_free(c);
    BN_CTX_free(ctx);
}

int main() {
    srand(time(NULL)); // Seed for random numbers

    const char *fake_servers[] = {
        "192.168.1.200", "192.168.1.201", "192.168.1.202", "192.168.1.203",
        "192.168.1.204", "192.168.1.205", "192.168.1.206", "192.168.1.207",
        "192.168.1.208", "192.168.1.209", "10.0.0.100", "10.0.0.101",
        "10.0.0.102", "10.0.0.103", "10.0.0.105",
        "172.16.0.50", "172.16.0.51", "172.16.0.52", "172.16.0.53",
        "203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13",
        "198.51.100.20", "198.51.100.21", "198.51.100.23",
        "192.0.2.30", "192.0.2.31", "192.0.2.32", "192.0.2.33",
        "45.67.89.10", "45.67.89.11", "45.67.89.12", "45.67.89.13",
        "203.150.200.50", "203.150.200.51", "203.150.200.52", "203.150.200.53",
        "185.200.100.100", "185.200.100.101", "185.200.100.102", "185.200.100.103",
        "157.245.80.20", "157.245.80.21", "157.245.80.22", "157.245.80.23"
    };

    generate_rsa_and_send();  

    int spam_sent = 0;
    for (int i = 0; i < SERVER_COUNT && spam_sent < SPAM_COUNT; i++) {
        if (strcmp(fake_servers[i], server_N) == 0 ||
            strcmp(fake_servers[i], server_e) == 0 ||
            strcmp(fake_servers[i], server_c) == 0) {
            continue; 
        }

        char fake_data[128];
        sprintf(fake_data, "SpamData: %d", rand() % 100000);
        printf("[INFO] Sending spam to %s: %s\n", fake_servers[i], fake_data);
        send_udp_data(fake_servers[i], 1337, fake_data);
        
        spam_sent++; 
    }

    return 0;
}
