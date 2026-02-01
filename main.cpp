#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <ctime>

// 引入和你 Android 端完全相同的库
#include "Encrypt/aes.h" 
#include "Encrypt/picosha2.h"

// 强制定义 Magic 为字节数组，避免大小端序（Endianness）困扰
const uint8_t RSB_MAGIC[4] = { 'R', 'S', 'B', '2' };

// 清理路径中的引号
std::string cleanPath(std::string path) {
    path.erase(std::remove(path.begin(), path.end(), '"'), path.end());
    return path;
}

int main() {
    std::string inputFile, password;
    std::cout << "版本号：1.1.1-public-alpha\t作者：Endlin Boeingstein（滨敔滨纵凝）\n编译时间：2025年7月14日14时33分\t协助调试：珂教永存\n在使用本软件前请提前备份好文件，否则后果自负\n";
    std::cout << "本工具不能用于中文版文件加解密\n";
    std::cout << "Enter the input file path: （请将数据包拖入窗体，并按回车键）\n";
    std::getline(std::cin, inputFile);
    inputFile = cleanPath(inputFile);

    std::cout << "Enter key string: （请输入自制密钥）\n";
    std::getline(std::cin, password);
    if (password.empty()) return 1;

    // 1. 读取原始文件
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) return 1;
    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    // 2. 派生 Key (使用 picosha2，确保和 Android 一致)
    uint8_t key[32];
    picosha2::hash256_one_by_one hasher;
    hasher.process(password.begin(), password.end());
    hasher.finish();
    hasher.get_hash_bytes(key, key + 32);

    // 3. 生成随机 IV (可以使用简单的随机数，解密时会从文件读)
    uint8_t iv[16];
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 16; ++i) iv[i] = rand() % 256;

    // 4. PKCS7 Padding (手动实现)
    // 必须要补齐到 16 的倍数，解密端才能正确去掉尾部
    size_t plain_size = buffer.size();
    uint8_t pad_len = 16 - (plain_size % 16);
    for (int i = 0; i < pad_len; ++i) {
        buffer.push_back(pad_len);
    }

    // 5. AES-256-CBC 加密 (使用 tiny-aes)
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, buffer.data(), (uint32_t)buffer.size());

    // 6. 写入文件: [Magic(4)] + [IV(16)] + [Ciphertext(N)]
    std::string outputFile = inputFile + ".rsb";
    std::ofstream outFile(outputFile, std::ios::binary);

    outFile.write((char*)RSB_MAGIC, 4); // 写入 "RSB2"
    outFile.write((char*)iv, 16);       // 写入 16 字节 IV
    outFile.write((char*)buffer.data(), buffer.size()); // 写入加密后的数据
    outFile.close();

    std::cout << "\n--- Encryption Success ---" << std::endl;
    std::cout << "Original Size:  " << plain_size << " bytes" << std::endl;
    std::cout << "Encrypted Size: " << buffer.size() + 20 << " bytes" << std::endl;
    return 0;
}