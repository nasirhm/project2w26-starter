#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "libsecurity.h"
#include "io.h"
#include "consts.h"

int state_sec = 0;
char *hostname = NULL;
EVP_PKEY *priv_key = NULL;
tlv *client_hello = NULL;
tlv *server_hello = NULL;
bool inc_mac = false;
static uint8_t client_nonce[NONCE_SIZE];
static uint8_t server_nonce[NONCE_SIZE];

static uint64_t read_be_uint(const uint8_t* bytes, size_t nbytes) {
    if (bytes == NULL || nbytes == 0 || nbytes > sizeof(uint64_t)) return 0;
    uint64_t v = 0;
    for (size_t i = 0; i < nbytes; i++) {
        v = (v << 8) | bytes[i];
    }
    return v;
}

static bool parse_lifetime_window(const tlv* life, uint64_t* start_ts, uint64_t* end_ts) {
    if (life == NULL || life->val == NULL || life->length != 16) return false;
    if (start_ts == NULL || end_ts == NULL) return false;
    uint64_t start = read_be_uint(life->val, 8);
    uint64_t end = read_be_uint(life->val + 8, 8);
    if (end < start) return false;
    *start_ts = start;
    *end_ts = end;
    return true;
}

static void enforce_lifetime_valid(const tlv* life) {
    uint64_t start_ts = 0;
    uint64_t end_ts = 0;
    if (!parse_lifetime_window(life, &start_ts, &end_ts)) exit(6);
    time_t now = time(NULL);
    if (now == (time_t) -1) exit(1);
    uint64_t now_u = (uint64_t) now;
    if (now_u < start_ts || now_u > end_ts) exit(1);
}

void init_sec(int initial_state, char* peer_host, bool bad_mac) {
    state_sec = initial_state;
    hostname = peer_host;
    inc_mac = bad_mac;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
        load_ca_public_key("ca_public_key.bin");
        generate_private_key();
        derive_public_key();
        priv_key = get_private_key();
    } else {
        load_certificate("server_cert.bin");
        load_ca_public_key("ca_public_key.bin");
        generate_private_key();
        derive_public_key();
        priv_key = get_private_key();
    }
}

ssize_t input_sec(uint8_t* out_buf, size_t out_cap) {
    switch ( state_sec ) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");
        if (client_hello != NULL) free_tlv(client_hello);
        client_hello = create_tlv(CLIENT_HELLO);

        tlv* ver = create_tlv(VERSION_TAG);
        uint8_t ver_val = PROTOCOL_VERSION;
        add_val(ver, &ver_val, 1);

        tlv* nonce = create_tlv(NONCE);
        generate_nonce(client_nonce, NONCE_SIZE);
        add_val(nonce, client_nonce, NONCE_SIZE);

        tlv* pub = create_tlv(PUBLIC_KEY);
        add_val(pub, public_key, pub_key_size);

        add_tlv(client_hello, ver);
        add_tlv(client_hello, nonce);
        add_tlv(client_hello, pub);

        uint16_t len = serialize_tlv(out_buf, client_hello);
        if (len > out_cap) return 0;
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return (ssize_t) len;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");
        if (server_hello != NULL) free_tlv(server_hello);
        server_hello = create_tlv(SERVER_HELLO);

        tlv* nonce = create_tlv(NONCE);
        generate_nonce(server_nonce, NONCE_SIZE);
        add_val(nonce, server_nonce, NONCE_SIZE);

        tlv* cert_t = create_tlv(CERTIFICATE);
        add_val(cert_t, certificate, cert_size);

        tlv* pub = create_tlv(PUBLIC_KEY);
        add_val(pub, public_key, pub_key_size);

        uint8_t transcript[5000];
        uint16_t offset = 0;
        offset += serialize_tlv(transcript + offset, client_hello);
        offset += serialize_tlv(transcript + offset, nonce);
        offset += serialize_tlv(transcript + offset, pub);

        uint8_t sig_buf[255];
        EVP_PKEY* eph_key = get_private_key();
        load_private_key("server_key.bin");
        size_t sig_len = sign(sig_buf, transcript, offset);
        set_private_key(eph_key);

        tlv* sig = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(sig, sig_buf, sig_len);

        add_tlv(server_hello, nonce);
        add_tlv(server_hello, cert_t);
        add_tlv(server_hello, pub);
        add_tlv(server_hello, sig);

        uint8_t salt[NONCE_SIZE * 2];
        memcpy(salt, client_nonce, NONCE_SIZE);
        memcpy(salt + NONCE_SIZE, server_nonce, NONCE_SIZE);
        derive_secret();
        derive_keys(salt, sizeof salt);

        uint16_t len = serialize_tlv(out_buf, server_hello);
        if (len > out_cap) return 0;
        state_sec = DATA_STATE;
        return (ssize_t) len;
    }
    case DATA_STATE: {
        uint8_t plain[1024];
        ssize_t plain_len = input_io(plain, sizeof plain);
        if (plain_len <= 0) return 0;

        uint8_t iv[IV_SIZE];
        uint8_t cipher[2048];
        size_t cipher_len = encrypt_data(iv, cipher, plain, (size_t) plain_len);

        tlv* iv_t = create_tlv(IV);
        add_val(iv_t, iv, IV_SIZE);
        tlv* ct_t = create_tlv(CIPHERTEXT);
        add_val(ct_t, cipher, cipher_len);

        uint8_t mac_input[3000];
        uint16_t mac_off = 0;
        mac_off += serialize_tlv(mac_input + mac_off, iv_t);
        mac_off += serialize_tlv(mac_input + mac_off, ct_t);

        uint8_t digest[MAC_SIZE];
        hmac(digest, mac_input, mac_off);
        if (inc_mac) digest[0] ^= 0xFF;

        tlv* mac_t = create_tlv(MAC);
        add_val(mac_t, digest, MAC_SIZE);

        tlv* data = create_tlv(DATA);
        add_tlv(data, iv_t);
        add_tlv(data, mac_t);
        add_tlv(data, ct_t);

        uint16_t len = serialize_tlv(out_buf, data);
        free_tlv(data);
        if (len > out_cap) return 0;
        return (ssize_t) len;
    }
    default:
        return (ssize_t) 0;
    }
}

void output_sec(uint8_t* in_buf, size_t in_len) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        print("RECV CLIENT HELLO");
        tlv* t = deserialize_tlv(in_buf, (uint16_t) in_len);
        if (t == NULL || t->type != CLIENT_HELLO) exit(6);
        if (client_hello != NULL) free_tlv(client_hello);
        client_hello = t;

        tlv* ver = get_tlv(t, VERSION_TAG);
        if (ver == NULL || ver->val == NULL || ver->length != 1) exit(6);
        if (ver->val[0] != PROTOCOL_VERSION) exit(6);

        tlv* nonce = get_tlv(t, NONCE);
        if (nonce == NULL || nonce->val == NULL || nonce->length != NONCE_SIZE) exit(6);
        memcpy(client_nonce, nonce->val, NONCE_SIZE);

        tlv* pub = get_tlv(t, PUBLIC_KEY);
        if (pub == NULL || pub->val == NULL || pub->length == 0) exit(6);
        load_peer_public_key(pub->val, pub->length);

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        print("RECV SERVER HELLO");
        tlv* t = deserialize_tlv(in_buf, (uint16_t) in_len);
        if (t == NULL || t->type != SERVER_HELLO) exit(6);
        if (server_hello != NULL) free_tlv(server_hello);
        server_hello = t;

        tlv* nonce = get_tlv(t, NONCE);
        tlv* cert = get_tlv(t, CERTIFICATE);
        tlv* pub = get_tlv(t, PUBLIC_KEY);
        tlv* sig = get_tlv(t, HANDSHAKE_SIGNATURE);
        if (nonce == NULL || cert == NULL || pub == NULL || sig == NULL) exit(6);
        if (nonce->val == NULL || nonce->length != NONCE_SIZE) exit(6);
        memcpy(server_nonce, nonce->val, NONCE_SIZE);
        if (sig->val == NULL || sig->length == 0) exit(6);

        tlv* dns = get_tlv(cert, DNS_NAME);
        tlv* cert_pub = get_tlv(cert, PUBLIC_KEY);
        tlv* life = get_tlv(cert, LIFETIME);
        tlv* cert_sig = get_tlv(cert, SIGNATURE);
        if (dns == NULL || cert_pub == NULL || life == NULL || cert_sig == NULL) exit(6);
        if (dns->val == NULL || dns->length == 0 || dns->val[dns->length - 1] != '\0') exit(6);
        enforce_lifetime_valid(life);

        uint8_t cert_buf[2000];
        uint16_t cert_off = 0;
        cert_off += serialize_tlv(cert_buf + cert_off, dns);
        cert_off += serialize_tlv(cert_buf + cert_off, cert_pub);
        cert_off += serialize_tlv(cert_buf + cert_off, life);
        if (verify(cert_sig->val, cert_sig->length, cert_buf, cert_off, ec_ca_public_key) != 1)
            exit(1);

        if (hostname == NULL || strcmp((char*) dns->val, hostname) != 0) exit(2);

        load_peer_public_key(cert_pub->val, cert_pub->length);
        EVP_PKEY* identity_key = ec_peer_public_key;

        uint8_t transcript[5000];
        uint16_t off = 0;
        if (client_hello == NULL) exit(6);
        off += serialize_tlv(transcript + off, client_hello);
        off += serialize_tlv(transcript + off, nonce);
        off += serialize_tlv(transcript + off, pub);
        if (verify(sig->val, sig->length, transcript, off, identity_key) != 1) exit(3);

        load_peer_public_key(pub->val, pub->length);
        derive_secret();
        uint8_t salt[NONCE_SIZE * 2];
        memcpy(salt, client_nonce, NONCE_SIZE);
        memcpy(salt + NONCE_SIZE, server_nonce, NONCE_SIZE);
        derive_keys(salt, sizeof salt);

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        tlv* t = deserialize_tlv(in_buf, (uint16_t) in_len);
        if (t == NULL || t->type != DATA) exit(6);

        tlv* iv_t = get_tlv(t, IV);
        tlv* mac_t = get_tlv(t, MAC);
        tlv* ct_t = get_tlv(t, CIPHERTEXT);
        if (iv_t == NULL || mac_t == NULL || ct_t == NULL) exit(6);
        if (iv_t->val == NULL || iv_t->length != IV_SIZE) exit(6);
        if (mac_t->val == NULL || mac_t->length != MAC_SIZE) exit(6);
        if (ct_t->val == NULL || ct_t->length == 0) exit(6);

        uint8_t mac_input[3000];
        uint16_t off = 0;
        off += serialize_tlv(mac_input + off, iv_t);
        off += serialize_tlv(mac_input + off, ct_t);
        uint8_t digest[MAC_SIZE];
        hmac(digest, mac_input, off);
        if (memcmp(digest, mac_t->val, MAC_SIZE) != 0) exit(5);

        uint8_t plain[2048];
        size_t plain_len = decrypt_cipher(plain, ct_t->val, ct_t->length, iv_t->val);
        output_io(plain, plain_len);
        free_tlv(t);
        break;
    }
    default:
        break;
    }
}
