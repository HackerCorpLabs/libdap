#ifndef APP_H
#define APP_H

#include <string>

struct AppConfig {
    std::string host = "localhost";
    int port = 4711;
    std::string program;
    bool debug = false;
};

AppConfig parse_args(int argc, char* argv[]);

class App {
public:
    App(const AppConfig& config);
    ~App();

    bool init();
    void run();
    void shutdown();

private:
    AppConfig config_;
    struct SDL_Window* window_ = nullptr;
    struct SDL_Renderer* renderer_ = nullptr;
    bool running_ = false;
};

#endif // APP_H
