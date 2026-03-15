#include "ui_main.h"
#include <imgui.h>
#include <cstring>

static ImVec4 direction_color(ProtocolEntry::Direction dir)
{
    switch (dir) {
    case ProtocolEntry::Sent:     return ImVec4(0.4f, 0.8f, 1.0f, 1.0f);
    case ProtocolEntry::Received: return ImVec4(0.5f, 1.0f, 0.5f, 1.0f);
    }
    return ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
}

static const char* direction_label(ProtocolEntry::Direction dir)
{
    switch (dir) {
    case ProtocolEntry::Sent:     return ">>>";
    case ProtocolEntry::Received: return "<<<";
    }
    return "???";
}

void PanelProtocol::render(DebuggerClient& client)
{
    if (!ImGui::Begin("DAP Protocol Log")) {
        ImGui::End();
        return;
    }

    // Controls
    if (ImGui::Button("Clear")) {
        client.clear_protocol_log();
    }
    ImGui::SameLine();
    ImGui::Checkbox("Auto-scroll", &auto_scroll_);
    ImGui::SameLine();
    ImGui::Checkbox("Sent", &show_sent_);
    ImGui::SameLine();
    ImGui::Checkbox("Received", &show_received_);

    ImGui::Separator();

    // Log area
    if (ImGui::BeginChild("##ProtocolLog", ImVec2(0, 0), ImGuiChildFlags_None,
                          ImGuiWindowFlags_HorizontalScrollbar)) {
        const auto& log = client.protocol_log();
        for (size_t i = 0; i < log.size(); i++) {
            const auto& entry = log[i];

            // Filter
            if (entry.direction == ProtocolEntry::Sent && !show_sent_) continue;
            if (entry.direction == ProtocolEntry::Received && !show_received_) continue;

            ImGui::PushID((int)i);

            ImVec4 color = direction_color(entry.direction);
            ImGui::TextColored(color, "%s", direction_label(entry.direction));
            ImGui::SameLine();

            // Show as collapsible tree for long entries, inline for short
            if (entry.json.size() > 120) {
                // Extract a summary: type + command/event
                std::string summary;
                // Quick parse for display label
                auto find_field = [&entry](const char* key) -> std::string {
                    std::string needle = std::string("\"") + key + "\"";
                    size_t pos = entry.json.find(needle);
                    if (pos == std::string::npos) return "";
                    pos = entry.json.find(':', pos);
                    if (pos == std::string::npos) return "";
                    pos = entry.json.find('"', pos);
                    if (pos == std::string::npos) return "";
                    size_t end = entry.json.find('"', pos + 1);
                    if (end == std::string::npos) return "";
                    return entry.json.substr(pos + 1, end - pos - 1);
                };

                std::string type = find_field("type");
                std::string cmd = find_field("command");
                std::string evt = find_field("event");
                if (!cmd.empty())
                    summary = type + ": " + cmd;
                else if (!evt.empty())
                    summary = type + ": " + evt;
                else
                    summary = type;

                if (ImGui::TreeNode(summary.c_str())) {
                    ImGui::TextWrapped("%s", entry.json.c_str());
                    ImGui::TreePop();
                }
            } else {
                ImGui::TextColored(color, "%s", entry.json.c_str());
            }

            ImGui::PopID();
        }

        // Auto-scroll
        if (log.size() != last_count_) {
            if (auto_scroll_) {
                ImGui::SetScrollHereY(1.0f);
            }
            last_count_ = log.size();
        }
    }
    ImGui::EndChild();

    ImGui::End();
}
