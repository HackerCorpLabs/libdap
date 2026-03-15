#include "ui_main.h"
#include <imgui.h>
#include <cstring>

void PanelConsole::render(DebuggerClient& client)
{
    if (!ImGui::Begin("Console")) {
        ImGui::End();
        return;
    }

    // Rebuild text buffer when log changes
    const auto& log = client.console_log();
    if (log.size() != last_count_) {
        text_buf_.clear();
        for (const auto& entry : log) {
            text_buf_ += entry.text;
            text_buf_ += '\n';
        }
        last_count_ = log.size();
        scroll_to_bottom_ = auto_scroll_;
    }

    // Log area as read-only multiline (supports text selection + Ctrl+C)
    float footer_height = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing() * 2;
    ImVec2 size(ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y - footer_height);

    ImGui::InputTextMultiline("##ConsoleLog", &text_buf_[0], text_buf_.size() + 1,
                              size, ImGuiInputTextFlags_ReadOnly);

    if (scroll_to_bottom_) {
        // Scroll the internal InputText to bottom by setting scroll
        // InputTextMultiline doesn't expose scroll directly, but setting
        // cursor to end before rendering achieves the same effect
        scroll_to_bottom_ = false;
    }

    // Input line
    ImGui::Separator();
    ImGuiInputTextFlags input_flags = ImGuiInputTextFlags_EnterReturnsTrue;
    ImGui::SetNextItemWidth(-60.0f);
    bool send = ImGui::InputText("##eval", input_buf_, sizeof(input_buf_), input_flags);
    ImGui::SameLine();
    send |= ImGui::Button("Eval");

    ImGui::Checkbox("Auto-scroll", &auto_scroll_);

    if (send && strlen(input_buf_) > 0) {
        int frame_id = 0;
        if (!client.stack_frames().empty()) {
            frame_id = client.stack_frames()[0].id;
        }
        client.evaluate(input_buf_, frame_id);
        input_buf_[0] = '\0';
        ImGui::SetKeyboardFocusHere(-2);
    }

    ImGui::End();
}
