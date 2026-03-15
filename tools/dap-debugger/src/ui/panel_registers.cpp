#include "ui_main.h"
#include <imgui.h>
#include <cstdio>

void PanelRegisters::render(DebuggerClient& client)
{
    if (!ImGui::Begin("Variables")) {
        ImGui::End();
        return;
    }

    if (client.state() == ClientState::Disconnected) {
        ImGui::TextDisabled("Not connected");
        ImGui::End();
        return;
    }

    const auto& scopes = client.scopes();
    if (scopes.empty()) {
        ImGui::TextDisabled("No variables available");
        ImGui::End();
        return;
    }

    // Refresh button
    bool stopped = client.state() == ClientState::Stopped;
    ImGui::BeginDisabled(!stopped);
    if (ImGui::Button("Refresh") && !client.stack_frames().empty()) {
        client.refresh_variables(client.stack_frames()[0].id);
    }
    ImGui::EndDisabled();

    ImGui::Separator();

    // Show each scope as a collapsible tree with its own variable table
    for (size_t s = 0; s < scopes.size(); s++) {
        const auto& scope = scopes[s];
        char label[256];
        snprintf(label, sizeof(label), "%s (%zu vars)###scope_%zu",
                 scope.name.c_str(), scope.variables.size(), s);

        if (ImGui::TreeNodeEx(label, ImGuiTreeNodeFlags_DefaultOpen)) {
            if (scope.variables.empty()) {
                ImGui::TextDisabled("  (empty)");
            } else {
                char table_id[64];
                snprintf(table_id, sizeof(table_id), "##vars_%zu", s);
                if (ImGui::BeginTable(table_id, 3,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
                    ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 130.0f);
                    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                    ImGui::TableHeadersRow();

                    for (const auto& v : scope.variables) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(v.name.c_str());
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(v.value.c_str());
                        ImGui::TableNextColumn();
                        ImGui::TextDisabled("%s", v.type.c_str());
                    }
                    ImGui::EndTable();
                }
            }
            ImGui::TreePop();
        }
    }

    ImGui::End();
}
