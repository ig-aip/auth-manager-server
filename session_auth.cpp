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

void Session_auth::handle_api() try {
    json json_resp;
    http::status status = http::status::ok;

    auto target = req.target();
    auto method = req.method();



    if(target == "/api/login" && method == http::verb::post){
        auto body = json::parse(req.body());
        std::string email = body.value("email", "");
        std::string password = body.value("password", "");
        auto login = server.database.logIn_user(email, password);

        std::string device_id = body.value("device_id", "");
        std::string device_name = body.value("device_name", "unknownDevice");
        std::string ip_address = ssl_stream.lowest_layer().remote_endpoint().address().to_string();

        if(device_id.empty()){
            status = http::status::bad_request;
            json_resp = {{"status", status}};
        }
        else if(login.first == true){
            std::string refresh_token = server.database.generateSession(login.second, device_id, device_name, ip_address);

            std::string access_token = jwt::create<jwt::traits::nlohmann_json>()
            .set_issuer("auth-manager-server")
            .set_type("JWS")
            .set_payload_claim("uuid", login.second)
            .set_payload_claim("did", device_id)
            .set_expires_at(std::chrono::system_clock::now() + std::chrono::minutes{1})
            .sign(jwt::algorithm::hs256(server.secret));

            json_resp = {{"status", "success"},
                         {"access_token", access_token},
                         {"refresh_token", refresh_token}};

        }else if(login.first == false){
            status = http::status::unauthorized;
            json_resp = {{"status", status}};
        }
    }

    else if(target == "/api/register" && method == http::verb::post){
        auto body = json::parse(req.body());
        std::string email = body.value("email", "");
        std::string password = body.value("password", "");
        std::string username = body.value("username", "");
        std::string uuid = boost::uuids::to_string(server.database.generate_uuid());
        std::string refresh_token = boost::uuids::to_string(server.database.generate_uuid());

        auto reg = server.database.register_user(username, email, password, uuid, refresh_token);

        std::string device_id = body.value("device_id", "");
        std::string device_name = body.value("device_name", "unknownDevice");
        std::string ip_address = ssl_stream.lowest_layer().remote_endpoint().address().to_string();

        if(reg.first == true){
            std::string refresh_token = server.database.generateSession(uuid, device_id, device_name, ip_address);

            std::string access_token = jwt::create<jwt::traits::nlohmann_json>()
                                           .set_issuer("auth-manager-server")
                                           .set_type("JWS")
                                           .set_payload_claim("uuid", uuid)
                                           .set_payload_claim("did", device_id)
                                           .set_expires_at(std::chrono::system_clock::now() + std::chrono::minutes{1})
                                           .sign(jwt::algorithm::hs256(server.secret));

            json_resp = {{"status", "success"},
                         {"access_token", access_token},
                         {"refresh_token", refresh_token}};

            std::cout << json_resp << std::endl;
        }
    }else if(target == "/api/refresh" && method == http::verb::post){
        if(req.body().empty()){
            json_resp = {{"out", "out"}};
        }else {
            auto body = json::parse(req.body());
            std::string old_refresh = body.value("refresh_token", "");
            std::string device_id = body.value("device_id", "");
            std::string ip_address = ssl_stream.lowest_layer().remote_endpoint().address().to_string();

            auto new_refresh = server.database.refresh_session(old_refresh, device_id, ip_address);
            if(new_refresh.first.empty()){

                std::string access_token = jwt::create<jwt::traits::nlohmann_json>()
                                               .set_issuer("auth-manager-server")
                                               .set_type("JWS")
                                               .set_payload_claim("uuid", new_refresh.second)
                                               .set_payload_claim("did", device_id)
                                               .set_expires_at(std::chrono::system_clock::now() + std::chrono::minutes{1})
                                               .sign(jwt::algorithm::hs256(server.secret));

                json_resp = {{"status", "success"},
                             {"access_token", access_token},
                             {"refresh_token", new_refresh.first}};
            }else{
                status = http::status::bad_request;
                json_resp = {"status", "not found"};
            }

        }
    }
    else if(target == "/api/refresh" && method == http::verb::get){
        auto body = json::parse(req.body());
        std::string refresh_token = body.value("refresh_token", "");
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

}catch(std::exception& ex){
    std::cerr << "exception in  handle error " << ex.what() <<"\n";
    do_close();
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
