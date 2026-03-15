#include "ui_main.h"
#include <imgui.h>

void PanelStack::render(DebuggerClient& client)
{
    if (!ImGui::Begin("Stack")) {
        ImGui::End();
        return;
    }

    if (client.state() == ClientState::Disconnected) {
        ImGui::TextDisabled("Not connected");
        ImGui::End();
        return;
    }

    const auto& frames = client.stack_frames();
    if (frames.empty()) {
        ImGui::TextDisabled("No stack frames");
        ImGui::End();
        return;
    }

    if (ImGui::BeginTable("##stack", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Location", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableHeadersRow();

        for (size_t i = 0; i < frames.size(); i++) {
            const auto& f = frames[i];
            ImGui::TableNextRow();

            bool is_selected = (selected_ == (int)i);
            ImGui::TableNextColumn();
            char label[32];
            snprintf(label, sizeof(label), "%zu", i);
            if (ImGui::Selectable(label, is_selected, ImGuiSelectableFlags_SpanAllColumns)) {
                selected_ = (int)i;
                if (client.state() == ClientState::Stopped) {
                    client.refresh_variables(f.id);
                }
            }

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(f.name.c_str());

            ImGui::TableNextColumn();
            ImGui::Text("0x%04X", f.instruction_pointer);

            ImGui::TableNextColumn();
            if (!f.source_name.empty() && f.line > 0) {
                ImGui::Text("%s:%d", f.source_name.c_str(), f.line);
            } else {
                ImGui::TextDisabled("--");
            }
        }
        ImGui::EndTable();
    }

    ImGui::End();
}
