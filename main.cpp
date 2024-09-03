/*
    HTTP (Hypertext Transfer Protocol) : it is a standard of application layer communication protocol
        for transmitting hyper media documents such as html, pdf, jpg between two or more networks,
        where one is the master or server and the rest are clients or slave.

        On websites that do not have a security certificate and are specified as HTTP,
        there is no password on the data shared between the transmitter and the server.
        In other words, all data is saved unencrypted. Not protected by any security protocol,
        these sites are vulnerable to external threats.

    HTTPS (Secure Hypertext Transfer Protocol) : It is the same as HTTP with more security.
        creates a safe environment for both itself and users through the security measures it takes.
        Thanks to the security protocol called SSL certificate,
        your website and computer are ideally protected against fiber attacks.

    Socket : It is a mechanism that most popular operating systems prove to give a programs
        access to the network. It allows messages to be sent and received between applications
        on the same or different networked machines. The sockets mechanism has been created to be
        independent of any specific type of network. IP addressing, however, is by far the most
        dominant network and the most popular use of sockets.

    - Steps of creating socket -
        1. Create the socket : There are 2 major and most important socket types.
            * Stream Socket : Connection oriented. TCP protocol is used.
              Provides a reliable, ordered, and error-checked delivery of a stream of bytes.
              Data is read in the same order it was sent.
              Commonly used for applications where reliable communication is critical,
              such as web servers (HTTP), email (SMTP), file transfer (FTP), and more.
            * Datagram Socket : Connectionless. UDP protocol is used.
              Provides an unreliable, unordered delivery of packets (datagrams).
              No guarantee of delivery, ordering, or duplicate protection.
              Suitable for applications where speed is more critical than reliability,
              such as real-time video streaming, online gaming, or Voice over IP (VoIP), TFTP, DHCP Client.
        2. Identify the socket : It is called also as binding and address. Once u have a socket,
            u might have to associate that socket with a port on your local machine.

            !! This is commonly done if you are going to listen() for incoming connections on a specific port
            example-multiplayer network games like GTA do this when they tell u to "connect to 192.168.5.10 port 3490"

            The port number is used by the kernel to match an incoming packet to a certain process's socket descriptor.
            If u r going to only be doing a connect() (because u r a client, not the server), this is probably be unnece

        3. On the server, wait for an incomming connection :
        4. Send and receive messages :
            send(): Used to send data over a network socket. Primarily used with TCP sockets, but can also be used with UDP sockets.
            sendto(): Used to send data to a specific address and port when using UDP sockets.
            recv(): Used to receive data from a network socket. Primarily used with TCP sockets, but can also be used with UDP sockets.
            recvfrom(): Used to receive data from a specific address and port when using UDP sockets.
            write(): Writes data to a file descriptor (used for files, pipes, and sockets).
            read(): Reads data from a file descriptor (used for files, pipes, and sockets).
            shutdown(): Gracefully shuts down a socket, partially or completely, to stop further sends and/or receives.
            close(): Closes a socket and releases all resources associated with it.
        5. Close the socket :

    ------------------- * ------------------- * ------------------- * ------------------- * ------------------- * ------------------- *

    Host Byte Order = native byte order (endianness) used by the architecture of the system. It can be :
        * Big Endian    = 0x12345678 -> network byte order
        * Little Endian = 0x78563412
        depends on your system architecture.

    Memory Address  |  Value
     0x00           |  0x12
     0x01           |  0x34
     0x02           |  0x56
     0x03           |  0x78

    ------------------- * ------------------- * ------------------- * ------------------- * ------------------- * ------------------- *

    - Port Numbers Range -
        Well-Known Ports (Reserved - 0-1023)
        Registered Ports (1024-49151) = Used by user applications or services
        Dynamic or Private Ports (49152-65535) = Temporary ports assigned dynamically by the operating system for short-lived connections.
 */

#include "server_info.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <vector>
#include <direct.h>
#include <fstream>
#include <filesystem>

constexpr int port_number = 8080;
constexpr int client_message_size = 1024;
constexpr int max_thread = 20;
std::mutex mutex;
int thread_count = 0;
std::vector<std::string> server_data_buffer;


std::string get_sub_str(const std::string& str, char token)
{
    int counter = 0;
    std::string sub_string;
    while (str[counter] != '\0')
    {
        if (str[counter] == token)
        {
            break;
        }
        sub_string += str[counter];
        counter++;
    }
    return sub_string;
}

std::string get_ext_folder_directory()
{
    return std::filesystem::current_path().parent_path().string() + "/test/ext";
}

std::string get_png_folder_directory()
{
    return std::filesystem::current_path().parent_path().string() + "/test/png";
}

void send_message(const SOCKET& socket, const std::string& file_path, const std::string& header_file)
{
    std::string header = server_messages[message_type::http_header] + header_file;
    std::string full_path = get_ext_folder_directory() + file_path;

    // Send header
    if (send(socket, header.c_str(), header.length(), 0) == SOCKET_ERROR)
    {
        std::cerr << "Error sending header: " << WSAGetLastError() << std::endl;
        return;
    }

    // Open file
    std::ifstream file(full_path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        std::cerr << "File could not open: " << full_path << std::endl;
        return;
    }

    std::filesystem::path path(full_path);
    auto file_size = std::filesystem::file_size(path);

    std::vector<char> buffer(4096);
    file.seekg(0, std::ios::beg);

    size_t bytes_remaining = file_size;
    while (bytes_remaining > 0)
    {
        size_t bytes_to_read = std::min(buffer.size(), bytes_remaining);
        file.read(buffer.data(), bytes_to_read);

        if (!file)
        {
            std::cerr << "Error reading file: " << WSAGetLastError() << std::endl;
            break;
        }

        size_t bytes_to_send = bytes_to_read;
        const char* buffer_ptr = buffer.data();

        while (bytes_to_send > 0)
        {
            ssize_t bytes_sent = send(socket, buffer_ptr, bytes_to_send, 0);
            if (bytes_sent == SOCKET_ERROR)
            {
                std::cerr << "Error sending file data: " << WSAGetLastError() << std::endl;
                return; // Terminate if sending fails
            }
            buffer_ptr += bytes_sent;
            bytes_to_send -= bytes_sent;
        }

        bytes_remaining -= bytes_to_read;
    }

    file.close();
}

void get_data(const std::string& request_type, std::string client_message)
{
    // "GET /search?query=apple&limit=10 HTTP/1.1"

    // Temporary variable to hold each key-value pair extracted from the data.
    // query-apple
    // limit-10
    std::string extract;

    // Copy the entire HTTP request message to the `data` variable for processing.
    std::string data = client_message;

    if (request_type == "GET")
    {
        // Remove the HTTP method ("GET") and the space following it from the data string.
        data.erase(0, get_sub_str(data, ' ').length() + 1); // "/search?query=apple&limit=10 HTTP/1.1"

        // Extract the URL from the data string (up to the next space character).
        data = get_sub_str(data, ' '); // "/search?query=apple&limit=10"

        // Remove everything before the '?' character (if any) to get only the query parameters.
        data.erase(0, get_sub_str(data, '?').length() + 1); // "query=apple&limit=10"
    }

    // "POST /submit?param1=value1&param2=value2 HTTP/1.1"
    else if (request_type == "POST")
    {
        int counter = data.length() - 1;

        // If data is exist
        while(counter > 0)
        {
            if (data[counter] == ' ' || data[counter] == '\n')
            {
                break;
            }
            counter--;
        }

        data.erase(0, counter + 1); // "HTTP/1.1"
        int found = data.find("=");

        // std::string::npos -> character or substring could not find.
        if (found == std::string::npos)
        {
            data = ""; // reset the data
        }
    }

    int found = client_message.find("cookie");
    if (found != std::string::npos) // if cookie is found
    {
        // Remove everything before the "cookie" keyword and move past "cookie: " (8 characters).
        client_message.erase(0, found + 8);
        // Extract the cookie string up to the next space character.
        client_message = get_sub_str(client_message, ' ');
        // Append the cookie string to the `data`, separated by '&' (assuming cookies are also key-value pairs).
        data = data + "&" + get_sub_str(client_message, '\n');
    }

    // if data exists
    while (data.length() > 0)
    {
        // "fruit-apple&speed-10"
        // Separate the key-value pair
        extract = get_sub_str(data, '&'); // fruit-apple
        // Store the key-value pair
        server_data_buffer.push_back(extract);
        // Pair is stored, now we can erase it.
        data.erase(0, get_sub_str(data, '&').length() + 1); // data = "speed-10"
    }
}

std::string find_mime_type(const std::string& file_extension)
{
    for (int i = 0; i <= sizeof(mime_types) / sizeof(mime_types[0]); ++i)
    {
        if (allowed_file_extensions[i] == file_extension)
        {
            return mime_types[i];
        }
    }

    std::cout << "serving ." << file_extension << " as html\n";
    return("MIME-Type : text/html\r\n\r\n");
}

DWORD WINAPI connection_handler(LPVOID socket_desc)
{
    // Cast the socket descriptor pointer to a SOCKET type and dereference it to get the actual socket handle.
    SOCKET new_socket = *static_cast<SOCKET*>(socket_desc);
    // Define a buffer to hold the incoming client message.
    char client_message[client_message_size];

    // Receive data from the socket into the client_message buffer.
    // 'recv' function receives up to (client_message_size - 1) bytes to ensure there's room for the null terminator.
    // The '0' flag indicates default behavior (blocking call).
    int request = recv(
            new_socket,
            client_message,
            client_message_size - 1,
            0);

    std::string message(client_message);

    mutex.lock();
    thread_count++;
    std::cout << "Thread Counter : " << thread_count << std::endl;

    if (thread_count > max_thread)
    {
        send(
                new_socket,
                server_messages[message_type::bad_request].c_str(),
                server_messages[message_type::bad_request].length(),
                0);

        thread_count--;
        closesocket(new_socket);
        mutex.unlock();
        ExitThread(0);
    }
    mutex.unlock();

    if(request == SOCKET_ERROR)
    {
        std::cerr << "Receive failed\n";
    }
    else if(request == 0)
    {
        std::cerr << "Client disconnected unexpectedly\n";
    }
    else
    {
        std::cout << "Client message : " << client_message << std::endl;
        std::string client_message_copy(client_message);
        size_t found = client_message_copy.find("manipulate/form-data");

        if (found != std::string::npos)
        {
            found = client_message_copy.find("Content-length:");
            client_message_copy.erase(0, found + 16); // delete "Content-length:"

            int length = std::stoi(get_sub_str(client_message_copy, ' '));
            found = client_message_copy.find("filename=");
            client_message_copy.erase(0, found + 10); // delete "filenamme="

            std::string new_file = get_sub_str(client_message_copy, '"');
            new_file = get_png_folder_directory() + new_file;
            found = client_message_copy.find("Content-Type:");
            client_message_copy.erase(0, found + 15); // delete "Content-Type:"
            client_message_copy.erase(0, get_sub_str(client_message_copy, '\n').length() + 3);

            char result_message[client_message_size];

            HANDLE written_file = CreateFile(
                    new_file.c_str(), GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

            if (written_file == INVALID_HANDLE_VALUE)
            {
                std::cerr << "Cannot open file path: " << new_file << std::endl;
            }
            else
            {
                DWORD written;
                WriteFile(written_file, client_message_copy.c_str(), client_message_size, &written, NULL);
                std::cout << "filesize: " << length << std::endl;

                int counter = 0;
                while (length > 0)
                {
                    int req = recv(new_socket, result_message, client_message_size, 0);
                    if (req == SOCKET_ERROR)
                    {
                        std::cerr << "Receive failed" << std::endl;
                        break;
                    }
                    WriteFile(written_file, result_message, req, &written, NULL);

                    length -= req;
                    counter += req;

                    std::cout << "remains: " << length << ". received size: " << req << ". total size received: " << counter << std::endl;
                    if (req < 1000)
                    {
                        break;
                    }
                }
                CloseHandle(written_file);
            }
        }

        // GET /server.html?site=udemy&a=b HTTP/1.1
        std::string request_type = get_sub_str(message, ' '); // GET
        message.erase(0, request_type.length()+1);
        std::string request_file = get_sub_str(message, ' '); // /server.html?site=udemy&a=b

        std::string request_file_copy(request_file);
        std::string file_extension_with_params = request_file_copy.erase(0, get_sub_str(request_file_copy, '.').length() + 1); // html?site=udemy&a=b
        std::string file_extension_only = get_sub_str(get_sub_str(file_extension_with_params, '/'), '?'); // html
        request_file = get_sub_str(request_file, '.') + "." + file_extension_only; // /server.html

        if (request_type == "GET" || request_type == "PUT")
        {
            if (request_file.length() <= 1)
            {
                request_file = "/index.html";
            }
            if (file_extension_only == "php")
            {
                // do nothing
                get_data(request_type, client_message);
            }

            mutex.lock();
            send_message(new_socket, request_file, find_mime_type(file_extension_only));
            mutex.unlock();
        }
    }
    std::cout << "\n -----exiting server--------\n";
    closesocket(new_socket);
    mutex.lock();
    thread_count--;
    mutex.unlock();
    ExitThread(0);
}

int main()
{

    WSADATA wsaData;
    int isInitialized = WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Before using any socket functions on Windows, we must initialize the Windows Sockets API (Winsock) using the WSAStartup function.
    // This step is not required on Unix-based systems like Linux or macOS.
    if (isInitialized != 0)
    {
        std::cerr << "ERROR : WSAStartup failed: " << isInitialized << std::endl;
        exit(EXIT_FAILURE);
    }

    // Creating the socket.
    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, 0); // Create a socket
    if (server_socket == INVALID_SOCKET)
    {
        std::cerr << "ERROR : Socket could not be created!!";
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    // When the server is shut down while running on a server,
    // kernel may not release the port. For example, on port 8080
    // running, when the server is shut down, the port is still “busy”.
    // can be reported, in which case the port will be busy when the server tries to restart.
    // because it may prevent it from being initialized.
    struct sockaddr_in server_address{}; // This structure is used to specify an endpoint address for network communication in IPv4.

    // Since I found it faster and easier to generate a random port number
    // in the project against this problem, I used this method.
    int random_port = port_number + (rand() % 10);
    // This initializes the server_address structure to zero.
    // This is a common practice to ensure that all fields are set to zero before assigning specific values.
    memset(&server_address, 0, sizeof server_address);

    server_address.sin_family = AF_INET; // Set address family IPv4 address
    server_address.sin_addr.s_addr = htonl(INADDR_ANY); // host-to-network-long
    server_address.sin_port = htons(random_port); // host-to-network-short

    while (bind(server_socket, (struct sockaddr *)& server_address, sizeof(server_address)) == SOCKET_ERROR) // It runs till binding.
    {
        random_port = port_number + (rand() % 10); // If binding fails, a new random port number is generated.
        server_address.sin_port = htons(random_port); // Updates the port number in the server_address structure with the new random port.
    }

    // Start listening for incoming connections on the server socket.
    // The second parameter specifies the maximum number of pending connections (10).
    if (listen(server_socket, 10) < 0)
    {
        std::cerr << "ERROR : Listening failed!!";
        closesocket(server_socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    // Structure to hold the client's address information.
    struct sockaddr_in client_address{};
    // Variable to store the client socket file descriptor.
    char ip4[INET_ADDRSTRLEN];

    SOCKET* thread_socket;

    while (true)
    {
        // Variable to store the size of the client address structure (on Windows, int is used. socklen_t len is unix based.)
        int len = sizeof(server_address);
        std::cout << random_port << " is listening...\n";
        // Accept an incoming connection and create a new socket for the client.
        auto client_socket = accept(server_socket, (struct sockaddr *)& client_address, &len);

        if (client_socket == INVALID_SOCKET)
        {
            std::cerr << "ERROR : unable to accept connection!!";
            return -1;
        }
        else
        {
            inet_ntop(AF_INET, &(client_address.sin_addr), ip4, INET_ADDRSTRLEN);
            std::cout << "connected to " << ip4 <<  "...\n";
        }

        thread_socket = new unsigned long long;
        *thread_socket = client_socket;

        HANDLE thread_handler = CreateThread(
                nullptr,
                0,
                connection_handler,
                thread_socket,
                0,
                nullptr
                );

        if (thread_handler == nullptr)
        {
            std::cerr << "Thread creation failed with error: " << GetLastError() << std::endl;
            return -1;
        }
    }
}
