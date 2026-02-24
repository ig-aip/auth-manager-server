#include "database.h"
#include "settings_auth.h"
std::string DataBase::hash_password(const std::string &password)
{
    //unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, EVP_sha256(), nullptr);
    EVP_DigestUpdate(context, password.c_str(), password.size());
    EVP_DigestFinal_ex(context, hash, &length);
    EVP_MD_CTX_free(context);

    std::stringstream ss;
    for(int i = 0; i < length; ++i){
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

std::string DataBase::hash_uuid(const std::string& uuid)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, EVP_sha256(), nullptr);
    EVP_DigestUpdate(context, uuid.c_str(), uuid.size());
    EVP_DigestFinal_ex(context, hash, &length);
    EVP_MD_CTX_free(context);

    std::stringstream ss;
    for(int i = 0; i < length; ++i){
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

boost::uuids::uuid DataBase::generate_uuid()
{
    boost::uuids::basic_random_generator<std::mt19937> gen;
    return gen();
}

bool DataBase::register_user(const std::string &username, const std::string &email, const std::string &password, const std::string& uuid)
{
    std::lock_guard<std::mutex> lock(db_mutex);
    try{
        std::cout << "user: " << username << "email: " << email << "password: " << password << std::endl;
        ScopedConnection sConn(*conn_pool);
        pqxx::work work(*sConn);
        pqxx::result result;

        result = work.exec_params("SELECT id FROM users WHERE username = $1", username);
        if(!result.empty()){
            return false;
        }

        result = work.exec_params("SELECT id FROM users WHERE email = $1", email);
        if(!result.empty()){
            return false;
        }


        std::string hashedPass = hash_password(password);
        std::string hashUUID = hash_uuid(uuid);

        std::cout << "uuid: " << hashUUID << " password: " << hashedPass << std::endl;

        result = work.exec_params("INSERT INTO users (username, email, password_hash, uuid) VALUES($1, $2, $3, $4) RETURNING id", username, email, hashedPass, hashUUID);
        std::cout << " id: "<< result[0][0].as<int>() << std::endl;
        work.commit();
        return true;

    }catch(std::exception ex){
        std::cerr << "error in get result from DataBase: " << ex.what() << std::endl;
        return false;
    }
}

bool DataBase::logIn_user(const std::string &email, const std::string &password)
{
    std::lock_guard<std::mutex> locl(db_mutex);
    try{
        ScopedConnection sConn(*conn_pool);
        pqxx::work work (*sConn);

        std::string hashed = hash_password(password);
        pqxx::result result = work.exec_params("SELECT id FROM users WHERE email = $1 AND password_hash = $2", email, hashed);
        if(result.empty()){
            return false;
        }
        return true;
    }catch(std::exception ex){
        std::cerr << "error in get result from DataBase: " << ex.what() << std::endl;
        return false;
    }
}

bool DataBase::hash_compare_uuid(const std::string &user_UUID, size_t id)
{

    ScopedConnection conn(*conn_pool);
    pqxx::work work(*conn);

    pqxx::result result = work.exec_params("SELECT uuid FROM users WHERE id = $1", id);

    if(result.empty()){
        std::cout << "hash compare uuid empty ;)" << std::endl;
        return false;
    }
    std::string hash_uuid_db = result[0][0].as<std::string>();

    if(hash_uuid_db == hash_uuid(user_UUID)){
        return true;
    }else{
        return false;
    }
}

bool DataBase::hash_compare_password(const std::string &user_password, const std::string& email)
{
    ScopedConnection conn(*conn_pool);
    pqxx::work work(*conn);

    pqxx::result result = work.exec_params("SELECT password_hash FROM users WHERE email = $1", email);
    if(result.empty()){
        std::cout << "hash compare password empty >:(" << std::endl;
        return false;
    }
    std::string hash_password_bd = result[0][0].as<std::string>();
    std::cout << "from db : " << hash_password_bd << std::endl;

    if(hash_password_bd == hash_password(user_password)){
        return true;
    }else{
        return false;
    }

}

std::string DataBase::get_uuid(const std::string &email)
{
    try {
        ScopedConnection conn(*conn_pool);
        pqxx::work work(*conn);

        pqxx::result result = work.exec_params("SELECT uuid FROM users WHERE email = $1", email);
        if(email.empty()){
            return "null";
        }

        return result[0][0].as<std::string>();
    } catch (std::exception ex) {
        return "null";
    }
}


//внещне изменяет строку использовать в последний момент
// bool DataBase::save_uuid(boost::uuids::uuid& uuid, size_t id){
//     std::lock_guard<std::mutex> lock(db_mutex);
//     try{
//         ScopedConnection sConn(*conn_pool);
//         pqxx::work work(*sConn);

//         std::string hashed = hash_uuid(boost::uuids::to_string(uuid));
//         pqxx::result result = work.exec_params("SELECT id FROM users WHERE ")

//     }catch(std::exception ex){

//     }
// }


DataBase::DataBase() :
    connection_str("postgresql://postgres:kotik123123@localhost:5432/audio-server"),
    conn_pool(std::make_unique<ConnectionPool>(connection_str, SQL_CONNECT_POOL_SIZE))
{
}

ScopedConnection::ScopedConnection(ConnectionPool& pool_):
    pool(pool_)
{
    conn = this->pool.getConn();
}

ScopedConnection::~ScopedConnection()
{
    pool.release(conn);
}

std::shared_ptr<pqxx::connection> ScopedConnection::operator ->()
{
    return pool.getConn();
}

pqxx::connection &ScopedConnection::operator*()
{
    return *conn;
}
