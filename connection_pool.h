#ifndef CONNECTION_POOL_H
#define CONNECTION_POOL_H
#include<pqxx/pqxx>
#include<queue>
#include<mutex>
#include<condition_variable>
#include<memory>
#include<iostream>

class ConnectionPool
{
    std::string connection_str;
    std::queue<std::shared_ptr<pqxx::connection>> pool;
    std::mutex mutex;
    std::condition_variable cond;
    size_t pool_size;
public:
    std::shared_ptr<pqxx::connection> getConn();
    void release(std::shared_ptr<pqxx::connection> oldConn);
    ConnectionPool(std::string conn_str, size_t size);
};

#endif // CONNECTION_POOL_H
