#include "app.h"
#include "debugger_client.h"
#include "ui/ui_main.h"

#include <SDL3/SDL.h>
#include <imgui.h>
#include <imgui_impl_sdl3.h>
#include <imgui_impl_sdlrenderer3.h>

#include <cstdio>
#include <cstring>
#include <getopt.h>

AppConfig parse_args(int argc, char* argv[])
{
    AppConfig cfg;
    static struct option long_opts[] = {
        {"host",    required_argument, nullptr, 'h'},
        {"port",    required_argument, nullptr, 'p'},
        {"program", required_argument, nullptr, 'P'},
        {"debug",   no_argument,       nullptr, 'd'},
        {"help",    no_argument,       nullptr, '?'},
        {nullptr, 0, nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "h:p:P:d", long_opts, nullptr)) != -1) {
        switch (opt) {
        case 'h': cfg.host = optarg; break;
        case 'p': cfg.port = atoi(optarg); break;
        case 'P': cfg.program = optarg; break;
        case 'd': cfg.debug = true; break;
        default:
            fprintf(stderr, "Usage: %s [--host HOST] [--port PORT] [--program FILE] [--debug]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    // Accept positional argument as program path
    if (cfg.program.empty() && optind < argc) {
        cfg.program = argv[optind];
    }
    return cfg;
}

App::App(const AppConfig& config)
    : config_(config)
{
}

App::~App()
{
    shutdown();
}

bool App::init()
{
    if (!SDL_Init(SDL_INIT_VIDEO)) {
        fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
        return false;
    }

    window_ = SDL_CreateWindow("DAP GUI Debugger", 1280, 800,
                               SDL_WINDOW_RESIZABLE);
    if (!window_) {
        fprintf(stderr, "SDL_CreateWindow failed: %s\n", SDL_GetError());
        return false;
    }

    renderer_ = SDL_CreateRenderer(window_, nullptr);
    if (!renderer_) {
        fprintf(stderr, "SDL_CreateRenderer failed: %s\n", SDL_GetError());
        return false;
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.IniFilename = "dap_gui_debugger.ini";

    ImGui::StyleColorsDark();

    ImGui_ImplSDL3_InitForSDLRenderer(window_, renderer_);
    ImGui_ImplSDLRenderer3_Init(renderer_);

    running_ = true;
    return true;
}

void App::run()
{
    DebuggerClient client;
    if (config_.debug) {
        client.set_debug(true);
    }

    UIMain ui;

    // Auto-connect if program was specified
    bool auto_connect = !config_.program.empty();

    while (running_) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL3_ProcessEvent(&event);
            if (event.type == SDL_EVENT_QUIT) {
                running_ = false;
            }
            if (event.type == SDL_EVENT_WINDOW_CLOSE_REQUESTED) {
                running_ = false;
            }
        }

        ImGui_ImplSDLRenderer3_NewFrame();
        ImGui_ImplSDL3_NewFrame();
        ImGui::NewFrame();

        // Auto-connect on first opportunity
        if (auto_connect && client.state() == ClientState::Disconnected) {
            client.connect(config_.host, config_.port);
            if (client.state() == ClientState::Connected) {
                client.initialize();
                if (client.state() == ClientState::Initialized) {
                    client.launch(config_.program);
                }
            }
            auto_connect = false;
        }

        client.poll();
        ui.render(client, config_);

        ImGui::Render();
        SDL_SetRenderDrawColor(renderer_, 30, 30, 30, 255);
        SDL_RenderClear(renderer_);
        ImGui_ImplSDLRenderer3_RenderDrawData(ImGui::GetDrawData(), renderer_);
        SDL_RenderPresent(renderer_);
    }

    if (client.state() != ClientState::Disconnected) {
        client.disconnect();
    }
}

void App::shutdown()
{
    if (renderer_) {
        ImGui_ImplSDLRenderer3_Shutdown();
        ImGui_ImplSDL3_Shutdown();
        ImGui::DestroyContext();
        SDL_DestroyRenderer(renderer_);
        renderer_ = nullptr;
    }
    if (window_) {
        SDL_DestroyWindow(window_);
        window_ = nullptr;
    }
    SDL_Quit();
}
