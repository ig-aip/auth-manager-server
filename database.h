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


class DataBase
{

    std::string connection_str;
    std::mutex db_mutex;

    std::unique_ptr<ConnectionPool> conn_pool;
    std::string hash_password(const std::string& password);
    std::string hash_uuid(const std::string& uuid);

    //bool save_uuid(boost::uuids::uuid& uuid, size_t id);


public:
    bool register_user(const::std::string& username, const std::string& email,  const std::string& password, const std::string& uuid);
    bool logIn_user(const std::string& email, const::std::string& password);

    bool hash_compare_uuid(const std::string& user_UUID, size_t id);
    bool hash_compare_password(const std::string& user_password, const std::string& email);

    std::string get_uuid(const std::string& email);

    boost::uuids::uuid generate_uuid();

    DataBase();
};






#endif // DATABASE_H
