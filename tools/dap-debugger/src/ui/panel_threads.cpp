#include "ui_main.h"
#include <imgui.h>
#include <cstdio>

void PanelThreads::render(DebuggerClient& client)
{
    if (!ImGui::Begin("Threads")) {
        ImGui::End();
        return;
    }

    if (client.state() == ClientState::Disconnected) {
        ImGui::TextDisabled("Not connected");
        ImGui::End();
        return;
    }

    bool stopped = client.state() == ClientState::Stopped;
    ImGui::BeginDisabled(!stopped);
    if (ImGui::Button("Refresh Threads")) {
        client.refresh_threads();
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::Text("Current thread: %d", client.thread_id());

    ImGui::Separator();

    const auto& threads = client.threads();
    if (threads.empty()) {
        ImGui::TextDisabled("No threads");
    } else {
        if (ImGui::BeginTable("##threads", 2,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 60.0f);
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (const auto& t : threads) {
                ImGui::TableNextRow();
                bool is_current = (t.id == client.thread_id());

                ImGui::TableNextColumn();
                ImVec4 color = is_current ? ImVec4(1.0f, 1.0f, 0.4f, 1.0f) : ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
                ImGui::TextColored(color, "%s%d", is_current ? ">" : " ", t.id);

                ImGui::TableNextColumn();
                ImGui::TextColored(color, "%s", t.name.c_str());
            }
            ImGui::EndTable();
        }
    }

    ImGui::End();
}
