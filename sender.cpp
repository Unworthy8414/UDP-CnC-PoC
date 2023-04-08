#include <asio.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>

std::string xor_cipher(const std::string &input, const std::string &key) {
    std::string output(input);
    for (size_t i = 0; i < input.length(); ++i) {
        output[i] = input[i] ^ key[i % key.length()];
    }
    return output;
}

std::string aes_encrypt(const std::string &input, const CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH]) {
    std::string ciphertext;
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::ECB_Mode_ExternalCipher::Encryption ecbEncryption(aesEncryption);
    CryptoPP::StreamTransformationFilter stfEncryptor(ecbEncryption, new CryptoPP::StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte *>(input.data()), input.length());
    stfEncryptor.MessageEnd();

    return ciphertext;
}

bool send_command(asio::io_context &io_context, const std::string &src_ip, uint16_t src_port,
                  const std::string &dst_ip, uint16_t dst_port, const std::string &command, int delay, const CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH]) {
    try {
        asio::ip::tcp::resolver resolver(io_context);
        auto endpoint_iterator = resolver.resolve(dst_ip, std::to_string(dst_port));
        asio::ip::tcp::socket socket(io_context);
        asio::connect(socket, endpoint_iterator);

        // Encrypt the command before sending
        std::string encrypted_command = aes_encrypt(command, key);
        asio::error_code ec;
        asio::write(socket, asio::buffer(encrypted_command), ec);

        if (!ec) {
            std::cout << "Sent command: " << command << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(delay));
            return true;
        } else {
            throw asio::system_error(ec);
        }
    } catch (asio::system_error &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
        return false;
    }
}

std::vector<std::string> read_commands_from_file(const std::string &file_path) {
    std::vector<std::string> commands;
    std::ifstream file(file_path);
    std::string line;
    while (std::getline(file, line)) {
        commands.push_back(line);
    }
    return commands;
}

int main(int argc, char *argv[]) {
    if (argc < 6) {
        std::cerr << "Usage: " << argv[0] << " <src_ip> <src_port> <dst_ip> <dst_port> <command_file> [delay]" << std::endl;
        return 1;
    }

    std::string src_ip = argv[1];
    uint16_t src_port = static_cast<uint16_t>(std::stoi(argv[2]));
    std::string dst_ip = argv[3];
    uint16_t dst_port = static_cast<uint16_t>(std::stoi(argv[4]));
    std::string command_file = argv[5];

    // 3. Add an optional delay argument
    int delay = 1;
    if (argc == 7) {
        delay = std::stoi(argv[6]);
    }

    const char *env_key = std::getenv("AES_KEY");
    if (!env_key) {
        std::cerr << "Error: Environment variable AES_KEY is not set" << std::endl;
        return 1;
    }
    std::string env_key_str(env_key);
    std::string aes_key_str = xor_cipher(env_key_str, "a_simple_key");
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    memcpy(key, aes_key_str.data(), CryptoPP::AES::DEFAULT_KEYLENGTH);

    // Read commands from the file
    std::vector<std::string> commands;
    try {
        commands = read_commands_from_file(command_file);
    } catch (const std::exception &e) {
        std::cerr << "Error reading commands from file: " << e.what() << std::endl;
        return 1;
    }

    asio::io_context io_context;

    for (const auto &command : commands) {
        send_command(io_context, src_ip, src_port, dst_ip, dst_port, command, delay, key);
    }

    io_context.run();

    return 0;
}