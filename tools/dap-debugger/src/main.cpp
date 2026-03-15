#include "app.h"
#include <cstdio>
#include <cstdlib>

int main(int argc, char* argv[])
{
    AppConfig config = parse_args(argc, argv);

    App app(config);
    if (!app.init()) {
        fprintf(stderr, "Failed to initialize application\n");
        return EXIT_FAILURE;
    }

    app.run();
    app.shutdown();
    return EXIT_SUCCESS;
}
