#include "connection_pool.h"

std::shared_ptr<pqxx::connection> ConnectionPool::getConn()
{
    std::unique_lock<std::mutex> lock(mutex);
    while(pool.empty()){
        cond.wait(lock);
    }

    auto conn = pool.front();

    if(!conn->is_open()){
        conn = std::make_shared<pqxx::connection>(connection_str);
    }

    return conn;
}

void ConnectionPool::release(std::shared_ptr<pqxx::connection> oldConn)
{
    if(!oldConn){ return; }
    try{
        if(oldConn->is_open()){
            pqxx::work work(*oldConn);
            work.exec("ROLLBACK");
            work.commit();
        }else{
            oldConn = std::make_shared<pqxx::connection>(connection_str);
        }
    }catch(std::exception& ex){
        std::cerr <<"error in release conn: " << ex.what() <<"\n";
    }

    std::unique_lock<std::mutex> lock(mutex);
    pool.push(oldConn);
    lock.unlock();
    cond.notify_one();
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
