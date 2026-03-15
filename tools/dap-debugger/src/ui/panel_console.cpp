#include "ui_main.h"
#include <imgui.h>
#include <cstring>

static ImVec4 category_color(ConsoleEntry::Category cat)
{
    switch (cat) {
    case ConsoleEntry::Info:        return ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
    case ConsoleEntry::Warning:     return ImVec4(1.0f, 0.8f, 0.2f, 1.0f);
    case ConsoleEntry::Error:       return ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
    case ConsoleEntry::DapEvent:    return ImVec4(0.4f, 0.7f, 1.0f, 1.0f);
    case ConsoleEntry::DapResponse: return ImVec4(0.5f, 0.9f, 0.5f, 1.0f);
    case ConsoleEntry::UserInput:   return ImVec4(1.0f, 1.0f, 0.6f, 1.0f);
    }
    return ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
}

void PanelConsole::render(DebuggerClient& client)
{
    if (!ImGui::Begin("Console")) {
        ImGui::End();
        return;
    }

    // Log area
    float footer_height = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();
    if (ImGui::BeginChild("##ConsoleLog", ImVec2(0, -footer_height), ImGuiChildFlags_None,
                          ImGuiWindowFlags_HorizontalScrollbar)) {
        const auto& log = client.console_log();
        for (const auto& entry : log) {
            ImGui::PushStyleColor(ImGuiCol_Text, category_color(entry.category));
            ImGui::TextWrapped("%s", entry.text.c_str());
            ImGui::PopStyleColor();
        }

        // Auto-scroll when new entries appear
        if (log.size() != last_count_) {
            if (auto_scroll_) {
                ImGui::SetScrollHereY(1.0f);
            }
            last_count_ = log.size();
        }
    }
    ImGui::EndChild();

    // Input line
    ImGui::Separator();
    ImGuiInputTextFlags input_flags = ImGuiInputTextFlags_EnterReturnsTrue;
    ImGui::SetNextItemWidth(-60.0f);
    bool send = ImGui::InputText("##eval", input_buf_, sizeof(input_buf_), input_flags);
    ImGui::SameLine();
    send |= ImGui::Button("Eval");

    if (send && strlen(input_buf_) > 0) {
        int frame_id = 0;
        if (!client.stack_frames().empty()) {
            frame_id = client.stack_frames()[0].id;
        }
        client.evaluate(input_buf_, frame_id);
        input_buf_[0] = '\0';
        ImGui::SetKeyboardFocusHere(-1);
    }

    ImGui::End();
}
