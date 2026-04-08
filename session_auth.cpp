#include "session_auth.h"
#include "server_auth.h"
#include "iostream"



Session_auth::Session_auth(Server_auth& server, tcp::socket&& socket, asio::ssl::context& contx) :
    server(server),
    ssl_stream(std::move(socket), contx),
    buff(4096)
{
    stream_timer = std::make_shared<asio::steady_timer>(ssl_stream.get_executor());
}

void Session_auth::run()
{
    set_timeout(30);
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

void Session_auth::set_timeout(size_t seconds)
{
    stream_timer->expires_after(std::chrono::seconds(seconds));
    auto self = shared_from_this();
    stream_timer->async_wait([self](boost::system::error_code er){
        if(er == boost::asio::error::operation_aborted) {
            return;
        }
        if(self->stream_timer->expiry() <= asio::steady_timer::clock_type::now()){
            std::cerr << "expried timer, clsoe connection" << '\n';
            boost::system::error_code ignore;
            self->ssl_stream.lowest_layer().close(ignore);
        }
    });
}

void Session_auth::do_read()
{
    req = {};
    set_timeout(30);
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
        else if(std::get<0>(login) == true){
             std::string user_uuid = server.database.get_uuid(email);

            std::string refresh_token = server.database.generateSession(user_uuid, device_id, device_name, ip_address);

            std::string access_token = generate_access_token(user_uuid, device_id, std::get<2>(login));

            json_resp = {{"status", "success"},
                         {"access_token", access_token},
                         {"refresh_token", refresh_token}};

        }else if(std::get<0>(login) == false){
            status = http::status::unauthorized;
            json_resp = {{"status", status}};
        }
    }

    else if(target == "/api/register" && method == http::verb::post){
        auto body = get_json(req.body());
        if(body.first){
            std::string email = body.second.value("email", "");
            std::string password = body.second.value("password", "");
            std::string username = body.second.value("username", "");
            std::string uuid = boost::uuids::to_string(server.database.generate_uuid());
            std::string refresh_token = boost::uuids::to_string(server.database.generate_uuid());

            auto reg = server.database.register_user(username, email, password, uuid, refresh_token);

            std::string device_id = body.second.value("device_id", "");
            std::string device_name = body.second.value("device_name", "unknownDevice");
            std::string ip_address = ssl_stream.lowest_layer().remote_endpoint().address().to_string();
            if(device_id.empty()){
                status = http::status::bad_request;
                json_resp = {{"status", status}};
            }
            else if(std::get<0>(reg) == true){
                std::string db_uuid = server.database.get_uuid(email);
                std::string refresh_token = server.database.generateSession(db_uuid, device_id, device_name, ip_address);

                std::string access_token = generate_access_token(db_uuid, device_id, std::get<2>(reg));

                json_resp = {{"status", "success"},
                             {"access_token", access_token},
                             {"refresh_token", refresh_token}};
            }
        }else{
            status = http::status::bad_request;
            json_resp = {{"status", "not found"}};
        }
    }else if(target == "/api/refresh" && method == http::verb::post){
        if(req.body().empty()){
            json_resp = {{"out", "out"}};
        }else {
            auto body = get_json(req.body());
            if(body.first){
                std::string old_refresh = body.second.value("refresh_token", "");
                std::string device_id = body.second.value("device_id", "");
                std::string ip_address = ssl_stream.lowest_layer().remote_endpoint().address().to_string();
                auto new_refresh = server.database.refresh_session(old_refresh, device_id, ip_address);
                if(device_id.empty() ){
                    status = http::status::bad_request;
                    json_resp = {{"status", status}};
                }
                else if(!std::get<0>(new_refresh).empty()){

                    std::string access_token = generate_access_token(std::get<1>(new_refresh), device_id, std::get<2>(new_refresh));

                    json_resp = {{"status", "success"},
                                 {"access_token", access_token},
                                 {"refresh_token", std::get<0>(new_refresh)}};
                }else{
                    status = http::status::bad_request;
                    json_resp = {{"status", "not found"}};
                }
            }else {
                status = http::status::bad_request;
                json_resp = {{"status", "not found"}};
            }
        }
    }
    else if(target == "/api/search/users" && method == http::verb::post){
        auto body = get_json(req.body());
        if(body.first){
            std::string query = body.second.value("query", "");
            auto users = server.database.search_users(query);
            json::array_t users_json;
            for(auto& u : users) {
                users_json.push_back({{"uuid", u.first}, {"username", u.second}});
            }
            json_resp = {{"users", users_json}};
            std::cout << "USERS: " << json_resp << std::endl;
            status = http::status::ok;
        } else {
            status = http::status::bad_request;
            json_resp = {{"status", "bad_request"}};
        }
    }
    else{
        status = http::status::not_found;
        json_resp = {{"status", "not found"}};
    }

    std::cout << "json: " << json_resp << std::endl;

    auto resp = std::make_shared<http::response<http::string_body>>(status, req.version());
    resp->set(http::field::server, "asio Igore-Corp authenticate server");
    resp->set(http::field::content_type, "application/json");
    resp->keep_alive(req.keep_alive());
    resp->body() = json_resp.dump();
    resp->prepare_payload();

    set_timeout(30);
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

std::string Session_auth::generate_access_token(const std::string &uuid, const std::string &device_id, const std::string& username)try
{
    std::string access_token = jwt::create<jwt::traits::nlohmann_json>()
    .set_issuer("auth-manager-server")
        .set_type("JWS")
        .set_payload_claim("username", username)
        .set_payload_claim("uuid", uuid)
        .set_payload_claim("did", device_id)
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::minutes{1})
        .sign(jwt::algorithm::hs256(server.secret));

    return access_token;
}catch(std::exception& ex){
    std::cout << " error in generate_access_token: " << ex.what()  << '\n';
}

std::pair<bool, json> Session_auth::get_json(const std::string &body)try
{
    json json_body = json::parse(body);
    return std::pair<bool, json> {true, json_body};
}catch(std::exception& ex){
    std::cerr << "error in get json, body: " << body << ",  ERR: " << ex.what() << '\n';
    return std::pair<bool, json> {false, {{}}};
}
