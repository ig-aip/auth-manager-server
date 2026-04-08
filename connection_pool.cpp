#include "connection_pool.h"

std::shared_ptr<pqxx::connection> ConnectionPool::getConn()
{
    std::cerr << "getConn start: " << pool.size() << '\n';
    std::unique_lock<std::mutex> lock(mutex);
    while(pool.empty()){
        cond.wait(lock);
    }

    auto conn = pool.front();
    pool.pop();

    lock.unlock();
    try{
        if(!conn || !conn->is_open()){
            conn = std::make_shared<pqxx::connection>(connection_str);
        }
    }catch(std::exception& ex){
        release(nullptr);
        std::cerr << "exception: " << ex.what();
        throw;
    }
    std::cerr << "getConn end: " << pool.size() << '\n';
    return conn;
}

void ConnectionPool::release(std::shared_ptr<pqxx::connection> oldConn)
{
    std::cerr << "release start: " << pool.size() << '\n';
    try{
        if(oldConn &&  oldConn->is_open()){
            pqxx::nontransaction work(*oldConn);
            work.exec("DISCARD ALL");
        }else{
            oldConn = std::make_shared<pqxx::connection>(connection_str);
        }
    }catch(std::exception& ex){
        std::cerr <<"error in release conn: " << ex.what() <<"\n";
        oldConn = nullptr;
    }

    std::unique_lock<std::mutex> lock(mutex);
    pool.push(oldConn);
    lock.unlock();
    cond.notify_one();
        std::cerr << "release end: " << pool.size() << '\n';
}

ConnectionPool::ConnectionPool(std::string conn_str, size_t size) :
    connection_str(conn_str),
    pool_size(size)
{
    for(size_t i = 0; i < pool_size; ++i){
        try {
            auto conn = std::make_shared<pqxx::connection>(connection_str);
            if(conn->is_open()){
                pool.push(conn);
            }
        } catch (std::exception& ex) {
            std::cerr << "Error in connection pool constructor: " << ex.what() << std::endl;
        }
    }
}
