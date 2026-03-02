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

std::string DataBase::hash_sha256(const std::string &base)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)base.c_str(), base.size(), hash);

    std::stringstream ss;

    for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i){
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

boost::uuids::uuid DataBase::generate_uuid()
{
    boost::uuids::basic_random_generator<std::mt19937> gen;
    return gen();
}

std::string DataBase::generateSession(size_t user_id, const std::string &device_id, const std::string &device_name, const std::string &ip)try
{
    ScopedConnection conn(*conn_pool);
    if(!conn->is_open()){ throw std::runtime_error("dataBase conn closed"); }

    std::string raw_refresh_token = boost::uuids::to_string(generate_uuid());
    std::string hash_refresh_token = hash_sha256(raw_refresh_token);

    pqxx::work work(*conn);

    std::string query = R"(
    INSERT INTO sessions (user_id, device_id, device_name, refresh_token_hash, ip_address, expires_at, last_active)
    VALUES($1, $2, $3, $4, $5, NOW() + INTERVAL '60 days', NOW())
    ON CONFLICT(user_id, device_id)
    DO UPDATE SET
        refresh_token_hash = EXCLUDED.refresh_token_hash,
        device_name = EXCLUDED.device_name,
        ip_address = EXCLUDED.ip_address,
        last_active = NOW(),
        expires_at = EXCLUDED.expires_at

    )";

    work.exec_params(query, user_id, device_id, device_name, ip);
    work.commit();

    return raw_refresh_token;

}catch(std::exception& ex){
    std::cerr << "error in generateSession: " << ex.what() << "\n";
    return "";
}

std::pair<std::string, size_t> DataBase::refresh_session(const std::string &old_rt, const std::string &current_device_id, const std::string &ip)try
{
    ScopedConnection conn(*conn_pool);
    if(!conn->is_open()){ throw std::runtime_error("dataBase conn closed"); }

    pqxx::work work(*conn);
    std::string old_hash = hash_sha256(old_rt);

    pqxx::result result = work.exec_params(R"(
    SELECT id FROM sessions WHERE device_id = $1 AND refresh_token = $2 AND expires_at > NOW())", current_device_id, old_hash);

    if(result.empty()){
        //мб добавть потом проверку на совпадение refresh_tokena, если не совпал значит какой то хацкер - убить все сессии
        return std::pair<std::string, size_t>{"", 0};
    }

    size_t session_id = result[0][0].as<std::size_t>();
    size_t user_id = result[0][1].as<size_t>();

    std::string new_raw_token = boost::uuids::to_string(generate_uuid());
    std::string new_hash_token = hash_sha256(new_raw_token);

    work.exec_params(R"(
    UPDATE sessions
    SET refresh_token_hash = $1, last_active = NOW(), ip_address = $2 WHERE id = $3)", new_hash_token,ip, session_id);

    work.commit();
    return std::pair<std::string, size_t>{new_raw_token, 0};


}catch(std::exception& ex){
    std::cerr << "error in refresh session: " << ex.what() << "\n";
    return std::pair<std::string, size_t>{"", 0};
}

std::vector<SessionInfo> DataBase::get_user_sessions(size_t user_id, const std::string &current_device_id)try
{
    std::vector<SessionInfo> sessions;
    ScopedConnection conn(*conn_pool);
    if(!conn->is_open()){ throw std::runtime_error("dataBase conn closed"); }

    pqxx::work work(*conn);
    pqxx::result result = work.exec_params(R"(
    SELECT device_name, device_id, ip_address, to_char(last_active, 'YYYY-MM-DD HH24:MI:SS')
    FROM sessions WHERE user_id = $1 ORDER BY last_active DESC
    )", user_id);

    for(const auto& raw : result){
        SessionInfo info;
        info.device_name = raw[0].c_str();
        info.device_id = raw[1].c_str();
        info.ip_adress = raw[2].c_str();
        info.last_active = raw[3].c_str();
        info.is_current = (info.device_id == current_device_id);
        sessions.push_back(info);
        sessions.emplace_back(raw[0].c_str(), raw[1].c_str(), raw[2].c_str(), raw[3].c_str(), (info.device_id == current_device_id));
    }

}catch(std::exception& ex){
    std::cerr << "error in refresh session: " << ex.what() << "\n";
    return std::vector<SessionInfo>{0};
}

bool DataBase::delete_session(size_t user_id, const std::string &device_id)try
{
    ScopedConnection conn(*conn_pool);
    if(!conn->is_open()){ throw std::runtime_error("dataBase conn closed"); }

    pqxx::work work(*conn);
    pqxx::result result = work.exec_params("DELETE FROM sessions WHERE user_id = $1 AND device_id = $2", user_id, device_id);
    work.commit();
    return true;

}catch(std::exception& ex){
    std::cerr << "error in delete session: " << ex.what() << "\n";
    return false;
}

std::pair<bool,size_t> DataBase::register_user(const std::string &username, const std::string &email, const std::string &password, const std::string& uuid, const std::string& refresh_token)try
{
    std::lock_guard<std::mutex> lock(db_mutex);

    std::cout << "user: " << username << "email: " << email << "password: " << password << std::endl;
    ScopedConnection sConn(*conn_pool);
    if(!sConn->is_open()){ throw std::runtime_error("dataBase conn closed"); }
    pqxx::work work(*sConn);
    pqxx::result result;

    result = work.exec_params("SELECT id FROM users WHERE username = $1", username);
    if(!result.empty()){
        return std::pair<bool,size_t>{false, 0};
    }

    result = work.exec_params("SELECT id FROM users WHERE email = $1", email);
    if(!result.empty()){
        return std::pair<bool,size_t>{false, 0};
    }


    std::string hashedPass = hash_password(password);
    std::string hashUUID = hash_uuid(uuid);

    std::cout << "uuid: " << hashUUID << " password: " << hashedPass << std::endl;

    result = work.exec_params("INSERT INTO users (username, email, password_hash, uuid, refresh_token) VALUES($1, $2, $3, $4, $5) RETURNING id"
                              , username, email, hashedPass, hashUUID, refresh_token);
    std::cout << " id: "<< result[0][0].as<int>() << std::endl;
    work.commit();
    return std::pair<bool,size_t>{true, result[0][0].as<std::size_t>()};


}catch(std::exception ex){
    std::cerr << "error in get result from DataBase: " << ex.what() << std::endl;
    return std::pair<bool,size_t>{false, 0};
}

std::pair<bool,size_t> DataBase::logIn_user(const std::string &email, const std::string &password)try
{
    std::lock_guard<std::mutex> locl(db_mutex);

    ScopedConnection sConn(*conn_pool);
    pqxx::work work (*sConn);
    if(!sConn->is_open()){ throw std::runtime_error("dataBase conn closed"); }

    std::string hashed = hash_password(password);
    pqxx::result result = work.exec_params("SELECT id FROM users WHERE email = $1 AND password_hash = $2", email, hashed);
    if(result.empty()){
        return std::pair<bool, size_t>{false, 0};
    }
    return std::pair<bool, size_t>{true, result[0][0].as<size_t>()};

}catch(std::exception ex){
    std::cerr << "error in get result from DataBase: " << ex.what() << std::endl;
    return std::pair<bool, size_t>{false, 0};
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
