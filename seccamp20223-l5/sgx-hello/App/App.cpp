#include <openssl/bio.h>
#include <sgx_urts.h>

#include <cstdio>
#include <cstring>
#include <iostream>

#include "Enclave_u.h"
#include "error_print.hpp"

sgx_enclave_id_t global_eid = 0;

void ocall_print(const char* str) {
    std::cout << "Output from OCALL: " << std::endl;
    std::cout << str << std::endl;
    return;
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

int main() {
    /* 以下の処理を実装する：
     * - Enclaveの作成（初期化）
     * - ECALL関数の呼び出し
     * - ECALL結果のSGXステータス及び戻り値の出力
     */
    if(initialize_enclave() < 0) {
        // printf("App: error, failed to initialize enclave.\n");
        std::cerr << "App: error, failed to initialize enclave." << std::endl;
        return -1;
    }
    const char* message = "Hello Enclave.";
    size_t message_len = strlen(message);
    int retval;

    sgx_status_t status = ecall_test(global_eid, &retval, message, message_len);
    print_sgx_status(status);
    // printf("Returned integer from ECALL is: %d\n", retval);
    std::cout << "Returned integer from ECALL is:" << retval << std::endl;

    sgx_destroy_enclave(global_eid);
    return 0;
}
