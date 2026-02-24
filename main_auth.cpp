#include "server_auth.h"

int main(int argc, char *argv[])
{
    auto server = std::make_shared<Server_auth>();
    server->start();
}
