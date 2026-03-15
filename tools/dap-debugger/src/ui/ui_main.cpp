#include "ui_main.h"
#include <imgui.h>
#include <imgui_internal.h>
#include <SDL3/SDL.h>
#include <cstdio>
#include <cstring>

UIMain::UIMain()
{
    panel_console_ = new PanelConsole();
    panel_stack_ = new PanelStack();
    panel_registers_ = new PanelRegisters();
    panel_source_ = new PanelSource();
    panel_breakpoints_ = new PanelBreakpoints();
    panel_terminal_ = new PanelTerminal();
    panel_threads_ = new PanelThreads();
    panel_protocol_ = new PanelProtocol();
    panel_symbols_ = new PanelSymbols();
    panel_server_info_ = new PanelServerInfo();
}

UIMain::~UIMain()
{
    delete panel_console_;
    delete panel_stack_;
    delete panel_registers_;
    delete panel_source_;
    delete panel_breakpoints_;
    delete panel_terminal_;
    delete panel_threads_;
    delete panel_protocol_;
    delete panel_symbols_;
    delete panel_server_info_;
}

void UIMain::setup_docking()
{
    ImGuiID dockspace_id = ImGui::GetID("MainDockSpace");

    // Only build layout if the dockspace has no saved layout yet
    ImGuiDockNode* node = ImGui::DockBuilderGetNode(dockspace_id);
    if (node && node->IsSplitNode())
        return;

    ImGui::DockBuilderRemoveNode(dockspace_id);
    ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspace_id, ImGui::GetMainViewport()->WorkSize);

    // Layout:
    //  +------------------+----------+
    //  |                  | Variables|
    //  |     Source       +----------+
    //  |                  |Stack/Thrd|
    //  |                  | /Brkpts  |
    //  +------------------+----------+
    //  |  Console / Terminal I/O     |
    //  +-----------------------------+

    ImGuiID dock_main = dockspace_id;
    ImGuiID dock_right = ImGui::DockBuilderSplitNode(dock_main, ImGuiDir_Right, 0.30f, nullptr, &dock_main);
    ImGuiID dock_bottom = ImGui::DockBuilderSplitNode(dock_main, ImGuiDir_Down, 0.30f, nullptr, &dock_main);
    ImGuiID dock_right_top = 0;
    ImGuiID dock_right_bottom = ImGui::DockBuilderSplitNode(dock_right, ImGuiDir_Down, 0.55f, nullptr, &dock_right_top);

    ImGui::DockBuilderDockWindow("Source", dock_main);
    ImGui::DockBuilderDockWindow("Variables", dock_right_top);
    ImGui::DockBuilderDockWindow("Stack", dock_right_bottom);
    ImGui::DockBuilderDockWindow("Threads", dock_right_bottom);
    ImGui::DockBuilderDockWindow("Breakpoints", dock_right_bottom);
    ImGui::DockBuilderDockWindow("Console", dock_bottom);
    ImGui::DockBuilderDockWindow("Terminal I/O", dock_bottom);
    ImGui::DockBuilderDockWindow("DAP Protocol Log", dock_bottom);
    ImGui::DockBuilderDockWindow("Symbols", dock_main);
    ImGui::DockBuilderDockWindow("Server Info", dock_right_top);

    ImGui::DockBuilderFinish(dockspace_id);
}

void UIMain::render(DebuggerClient& client, const AppConfig& config)
{
    // Full-window dockspace
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::SetNextWindowViewport(viewport->ID);

    ImGuiWindowFlags host_flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_MenuBar;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::Begin("DockSpaceHost", nullptr, host_flags);
    ImGui::PopStyleVar(3);

    ImGuiID dockspace_id = ImGui::GetID("MainDockSpace");
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_None);

    // Build the default dock layout after the dockspace exists
    setup_docking();

    render_menu_bar(client, config);

    ImGui::End();

    // Toolbar (non-docked, fixed at top of work area)
    render_toolbar(client);

    // Panels
    panel_source_->render(client);
    panel_registers_->render(client);
    panel_stack_->render(client);
    panel_console_->render(client);
    panel_breakpoints_->render(client);
    panel_terminal_->render(client);
    panel_threads_->render(client);
    panel_protocol_->render(client);
    panel_symbols_->render(client);
    panel_server_info_->render(client);

    // Status bar
    render_status_bar(client);

    // Keyboard shortcuts
    handle_keyboard_shortcuts(client, config);

    // Connect dialog
    if (show_connect_dialog_) {
        ImGui::OpenPopup("Connect to Server");
        show_connect_dialog_ = false;
    }
    if (ImGui::BeginPopupModal("Connect to Server", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Host", connect_host_, sizeof(connect_host_));
        ImGui::InputInt("Port", &connect_port_);
        ImGui::Separator();
        ImGui::InputText("Program (optional)", launch_program_, sizeof(launch_program_));
        ImGui::TextDisabled("Leave empty to connect without launching");

        if (ImGui::Button("Connect", ImVec2(200, 0))) {
            client.connect(connect_host_, connect_port_);
            if (client.state() == ClientState::Connected) {
                client.initialize();
                if (client.state() == ClientState::Initialized && launch_program_[0]) {
                    client.launch(launch_program_);
                }
            }
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    // Launch dialog
    if (show_launch_dialog_) {
        ImGui::OpenPopup("Launch Program");
        show_launch_dialog_ = false;
    }
    if (ImGui::BeginPopupModal("Launch Program", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Program path", launch_program_, sizeof(launch_program_));
        ImGui::TextDisabled("Leave empty to run without loading (e.g. boot from floppy)");
        ImGui::Separator();
        ImGui::InputText("Source file", launch_source_, sizeof(launch_source_));
        ImGui::InputText("Map file", launch_map_, sizeof(launch_map_));
        ImGui::InputText("Working directory", launch_cwd_, sizeof(launch_cwd_));
        ImGui::Checkbox("Stop on entry", &launch_stop_on_entry_);

        ImGui::Separator();
        if (ImGui::Button("Launch", ImVec2(120, 0))) {
            DebuggerClient::LaunchArgs largs;
            largs.program = launch_program_[0] ? launch_program_ : "boot";
            largs.source_file = launch_source_;
            largs.map_file = launch_map_;
            largs.cwd = launch_cwd_;
            largs.stop_on_entry = launch_stop_on_entry_;
            client.launch(largs);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void UIMain::handle_keyboard_shortcuts(DebuggerClient& client, const AppConfig& config)
{
    // Don't process shortcuts when typing in an input field
    if (ImGui::GetIO().WantTextInput) return;

    bool stopped = client.state() == ClientState::Stopped;
    bool running = client.state() == ClientState::Running;
    bool can_run = stopped || client.state() == ClientState::Initialized;

    if (ImGui::IsKeyPressed(ImGuiKey_F5) && can_run)  client.do_continue();
    if (ImGui::IsKeyPressed(ImGuiKey_F6) && running)   client.pause();
    if (ImGui::IsKeyPressed(ImGuiKey_F9) && stopped)   client.step_back();
    if (ImGui::IsKeyPressed(ImGuiKey_F10) && stopped)  client.step_over();
    if (ImGui::IsKeyPressed(ImGuiKey_F11) && stopped)  client.step_in();
    if (ImGui::IsKeyPressed(ImGuiKey_F11) && ImGui::GetIO().KeyShift && stopped) client.step_out();
}

void UIMain::render_menu_bar(DebuggerClient& client, const AppConfig& config)
{
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Connect...", nullptr, false,
                                client.state() == ClientState::Disconnected)) {
                show_connect_dialog_ = true;
            }
            if (ImGui::MenuItem("Launch...", nullptr, false,
                                client.state() == ClientState::Initialized)) {
                show_launch_dialog_ = true;
            }
            if (ImGui::MenuItem("Disconnect", nullptr, false,
                                client.state() != ClientState::Disconnected)) {
                client.disconnect();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Quit")) {
                SDL_Event quit_event;
                quit_event.type = SDL_EVENT_QUIT;
                SDL_PushEvent(&quit_event);
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Debug")) {
            bool stopped = client.state() == ClientState::Stopped;
            bool running = client.state() == ClientState::Running;
            bool can_run = stopped || client.state() == ClientState::Initialized;

            if (ImGui::MenuItem("Run", "F5", false, can_run)) client.do_continue();
            if (ImGui::MenuItem("Break", "F6", false, running)) client.pause();
            ImGui::Separator();
            if (ImGui::MenuItem("Step Over", "F10", false, stopped)) client.step_over();
            if (ImGui::MenuItem("Step In", "F11", false, stopped)) client.step_in();
            if (ImGui::MenuItem("Step Out", "Shift+F11", false, stopped)) client.step_out();
            if (ImGui::MenuItem("Step Back", "F9", false, stopped)) client.step_back();
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }
}

void UIMain::render_toolbar(DebuggerClient& client)
{
    ImGuiWindowFlags toolbar_flags = ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
    ImGui::Begin("##Toolbar", nullptr, toolbar_flags);

    bool disconnected = client.state() == ClientState::Disconnected;
    bool stopped = client.state() == ClientState::Stopped;
    bool running = client.state() == ClientState::Running;
    bool can_run = stopped || client.state() == ClientState::Initialized;

    if (disconnected) {
        if (ImGui::Button("Connect")) {
            show_connect_dialog_ = true;
        }
    } else {
        if (ImGui::Button("Disconnect")) {
            client.disconnect();
        }
    }

    ImGui::SameLine();
    ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
    ImGui::SameLine();

    // Run / Break
    ImGui::BeginDisabled(!can_run);
    if (ImGui::Button("Run (F5)")) client.do_continue();
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!running);
    if (ImGui::Button("Break (F6)")) client.pause();
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
    ImGui::SameLine();

    // Stepping
    ImGui::BeginDisabled(!stopped);
    if (ImGui::Button("Step Over")) client.step_over();
    ImGui::SameLine();
    if (ImGui::Button("Step In")) client.step_in();
    ImGui::SameLine();
    if (ImGui::Button("Step Out")) client.step_out();
    ImGui::SameLine();
    if (ImGui::Button("Step Back")) client.step_back();
    ImGui::EndDisabled();

    ImGui::End();
}

void UIMain::render_status_bar(DebuggerClient& client)
{
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    float height = ImGui::GetFrameHeight();
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + viewport->WorkSize.y - height));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, height));

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoBringToFrontOnFocus;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.0f, 2.0f));
    if (ImGui::Begin("##StatusBar", nullptr, flags)) {
        ImVec4 color;
        switch (client.state()) {
        case ClientState::Disconnected: color = ImVec4(0.6f, 0.6f, 0.6f, 1.0f); break;
        case ClientState::Connected:
        case ClientState::Initialized:  color = ImVec4(0.2f, 0.8f, 0.2f, 1.0f); break;
        case ClientState::Running:      color = ImVec4(0.2f, 0.6f, 1.0f, 1.0f); break;
        case ClientState::Stopped:      color = ImVec4(1.0f, 0.8f, 0.2f, 1.0f); break;
        case ClientState::Terminated:   color = ImVec4(1.0f, 0.3f, 0.3f, 1.0f); break;
        }
        ImGui::TextColored(color, "%s", client.state_string());

        if (!client.stop_reason().empty() && client.state() == ClientState::Stopped) {
            ImGui::SameLine();
            ImGui::Text("(%s)", client.stop_reason().c_str());
        }

        if (!client.stack_frames().empty()) {
            const auto& top = client.stack_frames()[0];
            ImGui::SameLine();
            ImGui::Text("| %s @ 0x%04X", top.name.c_str(), top.instruction_pointer);
            if (top.line > 0) {
                ImGui::SameLine();
                ImGui::Text("(%s:%d)", top.source_name.c_str(), top.line);
            }
        }

        if (!client.process_name().empty()) {
            ImGui::SameLine();
            ImGui::Text("| %s", client.process_name().c_str());
        }
    }
    ImGui::End();
    ImGui::PopStyleVar();
}
