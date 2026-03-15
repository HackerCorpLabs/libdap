#include "ui_main.h"
#include <imgui.h>
#include <imgui_internal.h>
#include <cstring>
#include <algorithm>

void PanelProtocol::render(DebuggerClient& client)
{
    if (!ImGui::Begin("DAP Protocol Log")) {
        ImGui::End();
        return;
    }

    // Controls row 1
    if (ImGui::Button("Clear")) {
        client.clear_protocol_log();
        text_buf_.clear();
        last_count_ = 0;
    }
    ImGui::SameLine();
    ImGui::Checkbox("Auto-scroll", &auto_scroll_);

    // Controls row 2: direction + type filters
    bool filter_changed = false;
    filter_changed |= ImGui::Checkbox("Sent", &show_sent_);
    ImGui::SameLine();
    filter_changed |= ImGui::Checkbox("Received", &show_received_);
    ImGui::SameLine();
    ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
    ImGui::SameLine();
    filter_changed |= ImGui::Checkbox("Requests", &show_requests_);
    ImGui::SameLine();
    filter_changed |= ImGui::Checkbox("Responses", &show_responses_);
    ImGui::SameLine();
    filter_changed |= ImGui::Checkbox("Events", &show_events_);

    // Controls row 3: text search
    ImGui::SetNextItemWidth(300.0f);
    if (ImGui::InputText("Search", search_buf_, sizeof(search_buf_))) {
        filter_changed = true;
    }

    ImGui::Separator();

    // Rebuild text buffer when log changes or filter changes
    const auto& log = client.protocol_log();
    if (log.size() != last_count_ || filter_changed) {
        text_buf_.clear();

        std::string search_lower;
        if (search_buf_[0]) {
            search_lower = search_buf_;
            std::transform(search_lower.begin(), search_lower.end(), search_lower.begin(),
                           [](unsigned char c) { return (char)tolower(c); });
        }

        for (const auto& entry : log) {
            // Direction filter
            if (entry.direction == ProtocolEntry::Sent && !show_sent_) continue;
            if (entry.direction == ProtocolEntry::Received && !show_received_) continue;

            // Type filter: detect message type from JSON content
            bool is_request = entry.json.find("\"type\":\t\"request\"") != std::string::npos
                           || entry.json.find("\"type\": \"request\"") != std::string::npos;
            bool is_response = entry.json.find("\"type\":\t\"response\"") != std::string::npos
                            || entry.json.find("\"type\": \"response\"") != std::string::npos;
            bool is_event = entry.json.find("\"type\":\t\"event\"") != std::string::npos
                         || entry.json.find("\"type\": \"event\"") != std::string::npos;

            if (is_request && !show_requests_) continue;
            if (is_response && !show_responses_) continue;
            if (is_event && !show_events_) continue;

            // Text search filter
            if (!search_lower.empty()) {
                std::string json_lower = entry.json;
                std::transform(json_lower.begin(), json_lower.end(), json_lower.begin(),
                               [](unsigned char c) { return (char)tolower(c); });
                if (json_lower.find(search_lower) == std::string::npos) continue;
            }

            text_buf_ += (entry.direction == ProtocolEntry::Sent) ? ">>> " : "<<< ";
            text_buf_ += entry.json;
            text_buf_ += "\n\n";
        }
        last_count_ = log.size();
    }

    // Selectable multiline text (supports Ctrl+C copy)
    ImVec2 size = ImGui::GetContentRegionAvail();
    ImGui::InputTextMultiline("##ProtocolLog", &text_buf_[0], text_buf_.size() + 1,
                              size, ImGuiInputTextFlags_ReadOnly);

    ImGui::End();
}
