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
    panel_memory_ = new PanelMemory();
    panel_cpu_tracing_ = new PanelCpuTracing();
    panel_watch_ = new PanelWatch();
    reg_watch_dialog_ = new RegisterWatchDialog();
    // Share the one register-watch dialog with the panels that can open it.
    panel_registers_->set_rw_dialog(reg_watch_dialog_);
    panel_breakpoints_->set_rw_dialog(reg_watch_dialog_);
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
    delete panel_memory_;
    delete panel_cpu_tracing_;
    delete panel_watch_;
    delete reg_watch_dialog_;
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
    ImGui::DockBuilderDockWindow("Debug Status", dock_right_top);
    ImGui::DockBuilderDockWindow("Watch", dock_right_top);
    ImGui::DockBuilderDockWindow("Memory", dock_main);
    ImGui::DockBuilderDockWindow("CPU Trace", dock_main);

    ImGui::DockBuilderFinish(dockspace_id);
}

void UIMain::render(DebuggerClient& client, const AppConfig& config)
{
    // Full-window dockspace -- reserve bottom line for status bar
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    float status_height = ImGui::GetFrameHeight();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, viewport->WorkSize.y - status_height));
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
    panel_memory_->render(client);
    panel_cpu_tracing_->render(client);
    panel_watch_->render(client);

    // Shared register-watch modal — drawn once per frame after the panels that open it.
    reg_watch_dialog_->render(client);

    // Detect disconnect for reconnect banner
    if (prev_state_ != ClientState::Disconnected && client.state() == ClientState::Disconnected) {
        show_reconnect_ = true;
    }
    prev_state_ = client.state();

    // Status bar
    render_status_bar(client);

    // Keyboard shortcuts
    handle_keyboard_shortcuts(client, config);

    // Connect dialog
    if (show_connect_dialog_) {
        connect_error_[0] = '\0';
        ImGui::OpenPopup("Connect to Server");
        show_connect_dialog_ = false;
    }
    if (ImGui::BeginPopupModal("Connect to Server", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Host", connect_host_, sizeof(connect_host_));
        ImGui::InputInt("Port", &connect_port_);
        ImGui::Separator();
        ImGui::InputText("Program (optional)", launch_program_, sizeof(launch_program_));
        ImGui::TextDisabled("Leave empty to connect without launching (use Attach for running emulators)");

        // Show error from previous attempt
        if (connect_error_[0]) {
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s", connect_error_);
            ImGui::Spacing();
        }

        if (ImGui::Button("Connect & Launch", ImVec2(200, 0))) {
            connect_error_[0] = '\0';
            client.connect(connect_host_, connect_port_);
            if (client.state() != ClientState::Connected) {
                snprintf(connect_error_, sizeof(connect_error_),
                         "Connection failed: %.200s:%d", connect_host_, connect_port_);
            } else {
                client.initialize();
                if (client.state() == ClientState::Initialized && launch_program_[0]) {
                    client.launch(launch_program_);
                }
                show_reconnect_ = false;
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Attach & Inspect", ImVec2(200, 0))) {
            connect_error_[0] = '\0';
            client.connect(connect_host_, connect_port_);
            if (client.state() != ClientState::Connected) {
                snprintf(connect_error_, sizeof(connect_error_),
                         "Connection failed: %.200s:%d", connect_host_, connect_port_);
            } else {
                client.initialize();
                if (client.state() == ClientState::Initialized) {
                    client.attach();
                    client.pause();
                    SDL_Delay(200);
                    client.poll();
                }
                show_reconnect_ = false;
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            connect_error_[0] = '\0';
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
    if (ImGui::IsKeyPressed(ImGuiKey_F9) && stopped && client.has_capability("supportsStepBack"))
        client.step_back();
    if (ImGui::IsKeyPressed(ImGuiKey_F10) && stopped)  client.step_over();
    if (ImGui::IsKeyPressed(ImGuiKey_F11) && ImGui::GetIO().KeyShift && stopped) client.step_out();
    else if (ImGui::IsKeyPressed(ImGuiKey_F11) && stopped)  client.step_in();
}

void UIMain::render_menu_bar(DebuggerClient& client, const AppConfig& config)
{
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Connect...", nullptr, false,
                                client.state() == ClientState::Disconnected)) {
                show_connect_dialog_ = true;
            }
            if (ImGui::MenuItem("Attach to Running...", nullptr, false,
                                client.state() == ClientState::Disconnected)) {
                attach_on_connect_ = true;
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
            bool can_step_back = stopped && client.has_capability("supportsStepBack");
            if (ImGui::MenuItem("Step Back", "F9", false, can_step_back)) client.step_back();
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
        // Reconnect button
        if (show_reconnect_ && !client.last_host().empty()) {
            ImGui::SameLine();
            if (ImGui::Button("Reconnect")) {
                client.connect(client.last_host(), client.last_port());
                if (client.state() == ClientState::Connected) {
                    client.initialize();
                    show_reconnect_ = false;
                }
            }
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f), "Connection lost");
        }
    } else {
        if (ImGui::Button("Disconnect")) {
            show_reconnect_ = false;
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

    // Stepping - capability-driven
    ImGui::BeginDisabled(!stopped);
    if (ImGui::Button("Step Over")) client.step_over();
    ImGui::SameLine();
    if (ImGui::Button("Step In")) client.step_in();
    ImGui::SameLine();
    if (ImGui::Button("Step Out")) client.step_out();
    ImGui::EndDisabled();
    ImGui::SameLine();
    bool can_step_back = stopped && client.has_capability("supportsStepBack");
    ImGui::BeginDisabled(!can_step_back);
    if (ImGui::Button("Step Back")) client.step_back();
    ImGui::EndDisabled();
    if (!can_step_back && stopped) {
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
            ImGui::SetTooltip("Server does not support reverse execution");
        }
    }

    ImGui::End();
}

void UIMain::render_status_bar(DebuggerClient& client)
{
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    float height = ImGui::GetFrameHeight();
    float y = viewport->WorkPos.y + viewport->WorkSize.y - height;
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, y));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, height));

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoFocusOnAppearing |
        ImGuiWindowFlags_NoDocking;

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
