#ifndef SERVER_AUTH_H
#define SERVER_AUTH_H
#include "net_auth.h"
#include "database.h"
#include "session_auth.h"

class Server_auth : public std::enable_shared_from_this<Server_auth>
{

    asio::io_context ioc;
    ip::tcp::acceptor acceptor;
    std::mutex mtx;
    ssl::context ctx;

    void start_acceptor();

public:
    DataBase database;
    void start();
    void load_server_certificate(asio::ssl::context& contx);
    Server_auth();

};


#endif // SERVER_AUTH_H
