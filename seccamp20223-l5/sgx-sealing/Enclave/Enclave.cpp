#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <string.h>

#include "Enclave_t.h"

int ecall_test(const char *message, size_t message_len) {
    ocall_print(message);
    return 1234;
}
/*
void ecall_print_sgx_status(sgx_status_t st) {
    ocall_print_sgx_status(st);
}
*/

uint32_t calc_sealed_len(uint32_t message_len) {
    return sgx_calc_sealed_data_size(0, message_len);
}

void sealing(uint8_t *message, uint32_t message_len, uint8_t *sealed, uint32_t sealed_len) {
    sgx_status_t status;
    status = sgx_seal_data(0, NULL, message_len, message, sealed_len, (sgx_sealed_data_t *)sealed);
}

uint32_t calc_unsealed_len(uint8_t *sealed, uint32_t sealed_len) {
    return sgx_get_encrypt_txt_len((sgx_sealed_data_t *)sealed);
}

void unsealing(uint8_t *sealed, uint32_t sealed_len, uint8_t *unsealed, uint32_t unsealed_len) {
    sgx_status_t status;
    status = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, 0, unsealed, &unsealed_len);
}

int verify(char *key, uint32_t key_len, char *password, uint32_t password_len, uint8_t *sealed, uint32_t sealed_len) {
    // message: sealedと比較したいやつ
    sgx_status_t status;
    uint32_t unsealed_len = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)sealed);
    uint8_t *unsealed = new uint8_t[unsealed_len]();
    status = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, 0, unsealed, &unsealed_len);
    char *unsealed_line_char = (char *)unsealed;

    char *tail_column_tk;
    char *recorded_key = strtok_r(unsealed_line_char, ",", &tail_column_tk);
    char *recorded_password = strtok_r(NULL, ",", &tail_column_tk);

    if(strcmp(key, recorded_key) == 0 && strcmp(password, recorded_password) == 0) {
        return 0;
    }

    return -1;
}

int get_password_len(char *key, uint32_t key_len, uint8_t *sealed, uint32_t sealed_len) {
    sgx_status_t status;
    uint32_t unsealed_len = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)sealed);
    uint8_t *unsealed = new uint8_t[unsealed_len]();
    char *unsealed_line_char = (char *)unsealed;
    status = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, 0, unsealed, &unsealed_len);

    char *tail_column_tk;
    char *recorded_key = strtok_r(unsealed_line_char, ",", &tail_column_tk);
    char *recorded_password = strtok_r(NULL, ",", &tail_column_tk);
    int password_len = 0;

    if(strcmp(key, recorded_key) == 0) {
        password_len = strlen(recorded_password);
    }
    return password_len;
}

void get_password(char *key, uint32_t key_len, uint8_t *sealed, uint32_t sealed_len, uint8_t *retval, uint32_t retval_len) {
    sgx_status_t status;
    uint32_t unsealed_len = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)sealed);
    uint8_t *unsealed = new uint8_t[unsealed_len]();
    char *unsealed_line_char = (char *)unsealed;
    status = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, 0, unsealed, &unsealed_len);

    char *tail_column_tk;
    char *recorded_key = strtok_r(unsealed_line_char, ",", &tail_column_tk);
    char *recorded_password = strtok_r(NULL, ",", &tail_column_tk);

    for(int i = 0; i < retval_len; ++i) {
        retval[i] = (uint8_t)recorded_password[i];
    }
}