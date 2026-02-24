#ifndef SESSION_AUTH_H
#define SESSION_AUTH_H
#include "net_auth.h"
#include "fstream"
#include "boost/uuid.hpp"
#include "jwt-cpp/jwt.h"
#include "jwt-cpp/base.h"
#include "jwt-cpp/traits/nlohmann-json/traits.h"

class Server_auth;


class Session_auth : public std::enable_shared_from_this<Session_auth>
{
    std::fstream file_stream;
    Server_auth& server;
    asio::ssl::stream<tcp::socket> ssl_stream;
    beast::flat_buffer buffer;
    http::request<http::string_body> req;
    std::vector<char> buff;
    std::shared_ptr<asio::steady_timer> stream_timer;
    void do_read();
    void do_close();

    void handle_api();

    std::string read_jwtSecret_from_file();


public:
    Session_auth(Server_auth& server, std::shared_ptr<ip::tcp::socket> socket, asio::ssl::context& contx);
    void run();
};



#endif // SESSION_AUTH_H
