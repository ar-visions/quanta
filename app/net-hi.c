#include <import>
#include <net>

int main(int argc, symbol argv[]) {
    A_start();
    map    args   = A_args(argc, argv, "server", string(""), null);
    string server = get(args, string("server"));
    print("connecting to %o", args);
    return 0;
}