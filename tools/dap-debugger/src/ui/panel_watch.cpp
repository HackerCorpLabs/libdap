#include "ui_main.h"
#include <imgui.h>
#include <cstdio>
#include <cstring>

void PanelWatch::render(DebuggerClient& client)
{
    if (!ImGui::Begin("Watch")) {
        ImGui::End();
        return;
    }

    if (client.state() == ClientState::Disconnected) {
        ImGui::TextDisabled("Not connected");
        ImGui::End();
        return;
    }

    // Add expression
    ImGui::SetNextItemWidth(200.0f);
    bool enter_pressed = ImGui::InputText("##watch_expr", expr_buf_, sizeof(expr_buf_),
                                           ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if ((ImGui::Button("Add") || enter_pressed) && expr_buf_[0]) {
        client.add_watch(expr_buf_);
        expr_buf_[0] = '\0';
        // Evaluate immediately if stopped
        if (client.state() == ClientState::Stopped) {
            client.evaluate_watches();
        }
    }

    ImGui::Separator();

    const auto& watches = client.watches();
    if (watches.empty()) {
        ImGui::TextDisabled("No watch expressions. Type an expression above or right-click a variable to add.");
        ImGui::End();
        return;
    }

    if (ImGui::BeginTable("##watches", 3,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Expression", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("##del", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableHeadersRow();

        int to_remove = -1;
        for (size_t i = 0; i < watches.size(); i++) {
            const auto& w = watches[i];
            ImGui::TableNextRow();

            ImVec4 val_color = w.changed ? ImVec4(1.0f, 0.4f, 0.2f, 1.0f)
                                         : ImVec4(0.8f, 0.8f, 0.8f, 1.0f);

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(w.expression.c_str());

            ImGui::TableNextColumn();
            if (w.value.empty()) {
                ImGui::TextDisabled("(not evaluated)");
            } else {
                ImGui::TextColored(val_color, "%s", w.value.c_str());
                if (w.changed) {
                    ImGui::SameLine();
                    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.2f, 0.7f), "*");
                }
            }

            ImGui::TableNextColumn();
            char btn_id[32];
            snprintf(btn_id, sizeof(btn_id), "X##wd_%zu", i);
            if (ImGui::SmallButton(btn_id)) {
                to_remove = (int)i;
            }
        }
        ImGui::EndTable();

        if (to_remove >= 0) {
            client.remove_watch((size_t)to_remove);
        }
    }

    ImGui::End();
}
