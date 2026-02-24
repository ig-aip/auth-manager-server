#include "session_auth.h"
#include "server_auth.h"
#include "iostream"



Session_auth::Session_auth(Server_auth& server, std::shared_ptr<ip::tcp::socket> socket, asio::ssl::context& contx) :
    server(server),
    ssl_stream(std::move(*socket), contx),
    buff(4096)
{
    stream_timer = std::make_shared<asio::steady_timer>(ssl_stream.get_executor());
}

void Session_auth::run()
{
    auto self = shared_from_this();
    ssl_stream.async_handshake(ssl::stream_base::server,
                               [self](boost::system::error_code er){
                                   if(!er){
                                       self->do_read();
                                   }else{
                                       std::cerr << "error in handshake: " << er.what() << std::endl;
                                   }
                               });
}

void Session_auth::do_read()
{
    req = {};
    auto self = shared_from_this();
    http::async_read(ssl_stream,
                     buffer,
                     req,
                     [self](beast::error_code er, size_t bytes){
                         boost::ignore_unused(bytes);
                         if(!er){
                             self->handle_api();

                         }
                         else if(er == http::error::end_of_stream || er == asio::ssl::error::stream_truncated){ self->do_close(); }
                         else{
                             std::cerr << "error in asyc read: " << er.what() << std::endl;
                         }
                     });
}

void Session_auth::handle_api(){
    json json_resp;
    http::status status = http::status::ok;

    auto target = req.target();
    auto method = req.method();



    if(target == "/api/login" && method == http::verb::get){
        auto body = json::parse(req.body());
        std::string email = body.value("email", "");
        std::string password = body.value("password", "");

        if(server.database.logIn_user(email, password)){

        }
    }

    else if(target == "/api/register" && method == http::verb::get){
        auto body = json::parse(req.body());
        std::string email = body.value("email", "");
        std::string password = body.value("password", "");
        std::string username = body.value("username", "");
        std::string uuid = boost::uuids::to_string(server.database.generate_uuid());

        if(server.database.register_user(username, email, password, uuid)){
            auto token = jwt::create<jwt::traits::nlohmann_json>()
            .set_issuer("auth-manager-server")
            .set_type("JWS")
            .set_payload_claim("uuid", uuid)
            .set_issued_at(std::chrono::system_clock::now())
            .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours{24})
            .sign(jwt::algorithm::hs256{read_jwtSecret_from_file()});

            json_resp = {{"status", "success"},
                         {"token", token}};

        }

    }

    else{
        status = http::status::not_found;
        json_resp = {"status", "not found"};
    }

    auto resp = std::make_shared<http::response<http::string_body>>(status, req.version());
    resp->set(http::field::server, "asio Igore-Corp authenticate server");
    resp->set(http::field::content_type, "application/json");
    resp->keep_alive(req.keep_alive());
    resp->body() = json_resp.dump();
    resp->prepare_payload();

    auto self = shared_from_this();

    http::async_write(ssl_stream, *resp,
                      [self, resp](beast::error_code er, size_t bytes){
                          if(!resp->keep_alive()){
                              self->do_close();
                          }else if(!er){
                              self->do_read();
                          }else if(er){
                              std::cerr << "error in handle write: " << er.what() << std::endl;
                          }
                      });

}

std::string Session_auth::read_jwtSecret_from_file()
{
    std::ifstream file;
    file.open("jwt_secret.txt", std::ios::in);
    if(!file.is_open()){
        throw std::exception{"file not open jwt_secrat.txt"};
    }

    std::string result;
    std::getline(file, result);
    return result;
}


void Session_auth::do_close()
{
    auto self = shared_from_this();
    ssl_stream.async_shutdown([self](beast::error_code er){
        if(er == beast::net::error::eof){ er = {}; }
        if(er){
            std::cerr << "error in shutdown: " << er.what() << std::endl;
        }
    });
}
