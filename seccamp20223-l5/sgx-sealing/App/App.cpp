#include <openssl/bio.h>
#include <sgx_tseal.h>
#include <sgx_urts.h>

#include <base64.cpp>
#include <base64.hpp>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>

#include "Enclave_u.h"
#include "error_print.hpp"

#define FIND_PASSWORD 0
#define REGISTER_KEY 1

std::string SEALING_DATA_FNAME = "sealing_data.txt";

sgx_enclave_id_t global_eid = 0;

void ocall_print(const char *str) {
    std::cout << "[Output from OCALL] ";
    std::cout << str << std::endl;
    BIO_dump_fp(stdout, (char *)str, strlen(str));
    return;
}
/*
void ocall_print_sgx_status(sgx_status_t st) {
    print_sgx_status(st);
}
*/

uint8_t *ocall_base64_decode(char *sealed_line_base64, uint32_t sealed_line_base64_len) {
    // return sealed_line (uint8_t*)
    size_t tmp;
    return base64_decode<uint8_t, char>(sealed_line_base64, tmp);
}

/* Enclave initialization function */
int initialize_enclave() {
    // 0埋めしたダミーの起動トークンでEnclaveを作成する
    sgx_launch_token_t token = {0};
    int updated = 0;
    std::string enclave_image_name = "enclave.signed.so";

    sgx_status_t status;

    status = sgx_create_enclave(enclave_image_name.c_str(), SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);

    if(status != SGX_SUCCESS) {
        // printf("App: error %#x, failed to create enclave.\n", status);
        std::cerr << "App: error" << status << ", failed to create enclave." << std::endl;
        return -1;
    }
    return 0;
}

void test() {
    std::string message_str = "HelloSealing";
    sgx_status_t status;

    // sealing -----------------------------------
    std::cout << "======"
              << "sealing"
              << "======" << std::endl;

    uint8_t *message;
    uint8_t *sealed;
    uint32_t message_len;
    uint32_t sealed_len;

    message = (uint8_t *)message_str.c_str();
    message_len = strlen((char *)message);
    status = calc_sealed_len(global_eid, &sealed_len, message_len);

    sealed = new uint8_t[sealed_len];
    status = sealing(global_eid, message, message_len, sealed, sealed_len);

    std::ofstream ofs(SEALING_DATA_FNAME, std::ios_base::app);
    if(!ofs) {
        std::cerr << "failed to open folder:" << SEALING_DATA_FNAME << std::endl;
        std::exit(1);
    }

    char *sealed_base64;
    sealed_base64 = base64_encode<char, uint8_t>(sealed, sealed_len);

    std::cout << sealed_base64 << std::endl;
    ofs << sealed_base64 << std::endl;
    ofs.close();

    // unsealing ------------------------------------
    std::cout << "======"
              << "unsealing"
              << "======" << std::endl;

    std::ifstream ifs(SEALING_DATA_FNAME, std::ios::binary);
    std::string sealed_str;

    size_t sealed_len2;

    while(std::getline(ifs, sealed_str, '\n')) {
        std::cout << sealed_str << std::endl;
        std::cout << "" << std::endl;
        sealed = base64_decode<uint8_t, char>((char *)sealed_str.c_str(), sealed_len2);

        uint32_t unsealed_len;
        uint8_t *unsealed;

        status = calc_unsealed_len(global_eid, &unsealed_len, sealed, sealed_len2);
        unsealed = new uint8_t[unsealed_len]();
        status = unsealing(global_eid, sealed, sealed_len, unsealed, unsealed_len);

        std::cout << unsealed << std::endl;
        // BIO_dump_fp(stdout, (char *)unsealed, unsealed_len);
    }
}

/* Sealing */
void sealing_process(std::string message_str) {
    uint8_t *message;
    uint8_t *sealed;
    uint32_t message_len;
    uint32_t sealed_len;
    char *sealed_base64;
    sgx_status_t status;

    message = (uint8_t *)message_str.c_str();
    message_len = strlen((char *)message);
    // message[message_len - 1] = '\0';
    status = calc_sealed_len(global_eid, &sealed_len, message_len);

    sealed = new uint8_t[sealed_len];
    status = sealing(global_eid, message, message_len, sealed, sealed_len);

    std::ofstream ofs(SEALING_DATA_FNAME, std::ios_base::app);
    if(!ofs) {
        std::cerr << "failed to open folder:" << SEALING_DATA_FNAME << std::endl;
        std::exit(1);
    }

    sealed_base64 = base64_encode<char, uint8_t>(sealed, sealed_len);
    ofs << sealed_base64 << std::endl;
    ofs.close();
    std::cout << "===== Sealing Successful! =====" << std::endl;
    std::cout << sealed_base64 << std::endl;
}

int main(int argc, char *argv[]) {
    if(initialize_enclave() < 0) {
        // printf("App: error, failed to initialize enclave.\n");
        std::cerr << "App: error, failed to initialize enclave." << std::endl;
        return -1;
    }

    std::string message_str;
    std::string key;
    std::string password;
    std::ifstream ifs(SEALING_DATA_FNAME);
    key = "SGXVAULTMASTER";
    if(!static_cast<bool>(ifs)) {
        std::cout << "Register your master password." << std::endl;
        std::cin >> password;
        message_str = key + "," + password;
        sealing_process(message_str);
        return 0;
    }
    std::cout << "Enter your master password." << std::endl;
    std::cin >> password;

    sgx_status_t status;
    int res;
    size_t sealed_len;
    uint8_t *sealed;
    std::string sealed_str;

    char masterkey_char[key.length() + 1];
    memcpy(masterkey_char, (char *)key.c_str(), key.length());
    uint32_t masterkey_char_len = key.length() + 1;
    masterkey_char[masterkey_char_len - 1] = '\0';

    char masterpassword_char[password.length() + 1];
    memcpy(masterpassword_char, (char *)password.c_str(), password.length());
    uint32_t masterpassword_char_len = password.length() + 1;
    masterpassword_char[masterpassword_char_len - 1] = '\0';

    while(std::getline(ifs, sealed_str, '\n')) {
        sealed = base64_decode<uint8_t, char>((char *)sealed_str.c_str(), sealed_len);

        uint32_t unsealed_len;
        uint8_t *unsealed;

        status = calc_unsealed_len(global_eid, &unsealed_len, sealed, sealed_len);
        unsealed = new uint8_t[unsealed_len]();
        // status = unsealing(global_eid, sealed, sealed_len, unsealed, unsealed_len);

        status = verify(global_eid, &res, masterkey_char, masterkey_char_len, masterpassword_char, masterpassword_char_len, sealed, sealed_len);

        if(res == 0) {
            break;
        }
    }
    if(res < 0) {
        std::cout << "pass failed" << std::endl;
        return -1;
    }

    ifs.clear();
    ifs.seekg(0, std::ios::beg);
    ifs.close();
    ifs.clear();

    int caseflag = 0;

    std::cout << "Select mode - 0: find password by key - 1: register your key and password." << std::endl;
    std::cin >> caseflag;

    if(caseflag == FIND_PASSWORD) {
        ifs.open(SEALING_DATA_FNAME);

        std::cout << "Enter your key." << std::endl;
        std::cin >> key;

        char key_char[key.length() + 1];
        memcpy(key_char, (char *)key.c_str(), key.length());
        uint32_t key_char_len = key.length() + 1;
        key_char[key_char_len - 1] = '\0';

        char password_char[password.length() + 1];
        memcpy(password_char, (char *)password.c_str(), password.length());
        uint32_t password_char_len = password.length() + 1;
        password_char[password_char_len - 1] = '\0';

        char *res_char;
        uint8_t *res_uint8t;
        int res_len;

        while(std::getline(ifs, sealed_str, '\n')) {
            sealed = base64_decode<uint8_t, char>((char *)sealed_str.c_str(), sealed_len);

            uint32_t unsealed_len;
            uint8_t *unsealed;

            status = calc_unsealed_len(global_eid, &unsealed_len, sealed, sealed_len);
            unsealed = new uint8_t[unsealed_len]();

            status = get_password_len(global_eid, &res_len, key_char, key_char_len, sealed, sealed_len);

            if(res_len > 0) {
                res_uint8t = new uint8_t[res_len]();

                status = get_password(global_eid, key_char, key_char_len, sealed, sealed_len, res_uint8t, res_len);

                for(int i = 0; i < res_len; i++) {
                    std::cout << res_uint8t[i];
                }
                std::cout << "" << std::endl;
            }
        }

    } else if(caseflag == REGISTER_KEY) {
        std::cout << "Register your key." << std::endl;
        std::cin >> key;
        std::cout << "Register your password." << std::endl;
        std::cin >> password;
        message_str = key + "," + password;
        sealing_process(message_str);
    }

    // print_sgx_status(status);
    sgx_destroy_enclave(global_eid);

    return 0;
}
