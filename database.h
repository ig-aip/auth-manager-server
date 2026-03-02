#ifndef DATABASE_H
#define DATABASE_H
#include <pqxx/pqxx>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <boost/asio.hpp>
#include <iostream>
#include <boost/uuid.hpp>
#include "connection_pool.h"



class ScopedConnection{
    std::shared_ptr<pqxx::connection> conn;
    ConnectionPool& pool;

public:
    ScopedConnection(ConnectionPool& pool_);
    ~ScopedConnection();


    std::shared_ptr<pqxx::connection> operator ->();

    pqxx::connection& operator*();

};


struct SessionInfo{
    std::string device_name;
    std::string device_id;
    std::string ip_adress;
    std::string last_active;
    bool is_current;
};


class DataBase
{

    std::string connection_str;
    std::mutex db_mutex;

    std::unique_ptr<ConnectionPool> conn_pool;
    std::string hash_password(const std::string& password);
    std::string hash_uuid(const std::string& uuid);


    std::string hash_sha256(const std::string& base);
    //bool save_uuid(boost::uuids::uuid& uuid, size_t id);


public:
    std::pair<bool,size_t> register_user(const::std::string& username, const std::string& email,  const std::string& password, const std::string& uuid, const std::string& refresh_token);
    std::pair<bool,size_t> logIn_user(const std::string& email, const::std::string& password);

    bool hash_compare_uuid(const std::string& user_UUID, size_t id);
    bool hash_compare_password(const std::string& user_password, const std::string& email);

    std::string get_uuid(const std::string& email);

    std::string getNewRefresh(const std::string& old);

    boost::uuids::uuid generate_uuid();

    std::string generateSession(size_t user_id, const std::string& device_id, const std::string& device_name, const std::string& ip);
    std::pair<std::string, size_t> refresh_session(const std::string& old_rt, const std::string& current_device_id, const std::string& ip);
    std::vector<SessionInfo> get_user_sessions(size_t user_id, const std::string& current_device_id);
    bool delete_session(size_t user_id, const std::string& device_id);
    bool delete_other_sessions(size_t user_id, const std::string& current_device_id);

    DataBase();
};






#endif // DATABASE_H
