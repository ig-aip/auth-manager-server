#include "server_auth.h"

int main(int argc, char *argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    auto server = std::make_shared<Server_auth>();
    server->start();
}
