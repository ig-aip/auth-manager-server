#include "server_auth.h"

#include "Server_auth.h"
#include "algorithm"


Server_auth::Server_auth()  :
    ioc(),
    acceptor(ioc),
    ctx(ssl::context::tls_server)
{
    boost::system::error_code er;
    acceptor.open(ip::tcp::endpoint{ip::make_address_v4(IP), PORT}.protocol(), er);

    if(er){
        throw std::runtime_error("error in open acceptor:" + er.what());
    }

    acceptor.set_option(asio::socket_base::reuse_address(true), er);
    if(er){
        throw std::runtime_error("error in open set option:" + er.what());
    }

    acceptor.bind(ip::tcp::endpoint{ip::make_address_v4(IP), PORT}, er);
    if(er){
        throw std::runtime_error("error in bind:" + er.what());
    }

    acceptor.listen(asio::socket_base::max_listen_connections, er);
    if(er){
        throw std::runtime_error("error in listen:" + er.what());
    }


}


void Server_auth::start_acceptor()
{

    auto sock = std::make_shared<ip::tcp::socket>(ioc);
    auto self = shared_from_this();
    acceptor.async_accept(*sock, [self, sock](boost::system::error_code er){
        if(!er){
            auto session = std::make_shared<Session_auth>(*self, sock, self->ctx);
            session->run();
            self->start_acceptor();
        }else{
            throw std::runtime_error("error in accept: " + er.message());
        }
    });
}

void Server_auth::start()
{

    load_server_certificate(ctx);
    start_acceptor();

    unsigned int threads = std::max(1u, std::thread::hardware_concurrency());
    std::vector<std::thread> pool;
    pool.reserve(threads);
    auto self = shared_from_this();
    for(int i = 0 ; i < threads; ++i){
        pool.emplace_back([self]() -> void{
            try {
                self->ioc.run();
            }
            catch (std::exception ex) {
                std::cerr << "error int start poll threads: " << std::endl;
            }
        });
    }


    for(auto& t : pool){
        t.join();
    }
}


void Server_auth::load_server_certificate(asio::ssl::context& contx){
    try {
        contx.set_options(asio::ssl::context::default_workarounds |
                          asio::ssl::context::no_sslv2 |
                          asio::ssl::context::single_dh_use);
        contx.use_certificate_chain_file("server.crt");
        contx.use_private_key_file("server.key", asio::ssl::context::pem);
    }
    catch (std::exception ex) {
        std::cout << "exception in load certificate" << std::endl;
    }

}
