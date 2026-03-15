#include "ui_main.h"
#include <imgui.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>

void PanelBreakpoints::render(DebuggerClient& client)
{
    if (!ImGui::Begin("Breakpoints")) {
        ImGui::End();
        return;
    }

    if (client.state() == ClientState::Disconnected) {
        ImGui::TextDisabled("Not connected");
        ImGui::End();
        return;
    }

    if (ImGui::BeginTabBar("##bp_tabs")) {
        // --- Source Breakpoints Tab ---
        if (ImGui::BeginTabItem("Source")) {
            ImGui::SetNextItemWidth(200.0f);
            ImGui::InputText("File", source_buf_, sizeof(source_buf_));
            ImGui::SameLine();
            ImGui::SetNextItemWidth(80.0f);
            ImGui::InputInt("Line", &line_buf_);
            ImGui::SameLine();
            if (ImGui::Button("Add##src")) {
                if (strlen(source_buf_) > 0 && line_buf_ > 0) {
                    client.add_source_breakpoint(source_buf_, line_buf_);
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Clear All##src")) {
                if (strlen(source_buf_) > 0) {
                    client.clear_breakpoints(source_buf_);
                }
            }

            ImGui::Separator();
            const auto& bps = client.breakpoints();
            if (bps.empty()) {
                ImGui::TextDisabled("No source breakpoints");
            } else {
                if (ImGui::BeginTable("##src_bps", 6,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
                    ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 35.0f);
                    ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Line", ImGuiTableColumnFlags_WidthFixed, 50.0f);
                    ImGui::TableSetupColumn("Condition", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                    ImGui::TableSetupColumn("##del", ImGuiTableColumnFlags_WidthFixed, 30.0f);
                    ImGui::TableHeadersRow();

                    int to_remove = -1;
                    for (const auto& bp : bps) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn(); ImGui::Text("%d", bp.id);
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(bp.source_path.c_str());
                        ImGui::TableNextColumn(); ImGui::Text("%d", bp.line);
                        ImGui::TableNextColumn();
                        if (!bp.condition.empty()) ImGui::TextUnformatted(bp.condition.c_str());
                        else ImGui::TextDisabled("--");
                        ImGui::TableNextColumn();
                        if (bp.verified)
                            ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "OK");
                        else
                            ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.2f, 1.0f), "Pend");
                        ImGui::TableNextColumn();
                        char del_label[32];
                        snprintf(del_label, sizeof(del_label), "X##s%d", bp.id);
                        if (ImGui::SmallButton(del_label)) {
                            to_remove = bp.id;
                        }
                    }
                    ImGui::EndTable();

                    if (to_remove >= 0) {
                        client.remove_source_breakpoint(to_remove);
                    }
                }
            }
            ImGui::EndTabItem();
        }

        // --- Instruction Breakpoints Tab ---
        if (ImGui::BeginTabItem("Instruction")) {
            static uint32_t addr_buf = 0;
            ImGui::SetNextItemWidth(120.0f);
            ImGui::InputScalar("Address", ImGuiDataType_U32, &addr_buf, nullptr, nullptr, "0x%04X",
                               ImGuiInputTextFlags_CharsHexadecimal);
            ImGui::SameLine();
            if (ImGui::Button("Add##inst")) {
                if (addr_buf > 0) {
                    auto ibps = client.instruction_breakpoints();
                    InstructionBreakpointInfo ibi;
                    ibi.instruction_reference = addr_buf;
                    ibi.offset = 0;
                    ibi.id = -1;
                    ibi.verified = false;
                    ibps.push_back(ibi);
                    client.set_instruction_breakpoints(ibps);
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Clear All##inst")) {
                client.set_instruction_breakpoints({});
            }

            ImGui::Separator();
            const auto& ibps = client.instruction_breakpoints();
            if (ibps.empty()) {
                ImGui::TextDisabled("No instruction breakpoints");
            } else {
                if (ImGui::BeginTable("##inst_bps", 5,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
                    ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 35.0f);
                    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableSetupColumn("Condition", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                    ImGui::TableSetupColumn("##del", ImGuiTableColumnFlags_WidthFixed, 30.0f);
                    ImGui::TableHeadersRow();

                    int to_remove_idx = -1;
                    for (size_t i = 0; i < ibps.size(); i++) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn(); ImGui::Text("%d", ibps[i].id);
                        ImGui::TableNextColumn(); ImGui::Text("0x%04X", ibps[i].instruction_reference);
                        ImGui::TableNextColumn();
                        if (!ibps[i].condition.empty()) ImGui::TextUnformatted(ibps[i].condition.c_str());
                        else ImGui::TextDisabled("--");
                        ImGui::TableNextColumn();
                        if (ibps[i].verified)
                            ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "OK");
                        else
                            ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.2f, 1.0f), "Pend");
                        ImGui::TableNextColumn();
                        char del_label[32];
                        snprintf(del_label, sizeof(del_label), "X##i%d", (int)i);
                        if (ImGui::SmallButton(del_label)) {
                            to_remove_idx = (int)i;
                        }
                    }
                    ImGui::EndTable();

                    if (to_remove_idx >= 0) {
                        auto copy = ibps;
                        copy.erase(copy.begin() + to_remove_idx);
                        client.set_instruction_breakpoints(copy);
                    }
                }
            }
            ImGui::EndTabItem();
        }

        // --- Data Breakpoints (Watchpoints) Tab ---
        if (ImGui::BeginTabItem("Watchpoints")) {
            static char data_id_buf[64] = {};
            static int access_type = 1; // write
            ImGui::SetNextItemWidth(120.0f);
            ImGui::InputText("Address/ID", data_id_buf, sizeof(data_id_buf));
            ImGui::SameLine();
            ImGui::SetNextItemWidth(100.0f);
            const char* access_items[] = { "Read", "Write", "ReadWrite" };
            ImGui::Combo("Access", &access_type, access_items, 3);
            ImGui::SameLine();
            if (ImGui::Button("Add##data")) {
                if (strlen(data_id_buf) > 0) {
                    client.add_data_breakpoint(data_id_buf, access_type);
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Clear All##data")) {
                client.clear_data_breakpoints();
            }

            ImGui::Separator();
            const auto& dbps = client.data_breakpoints();
            if (dbps.empty()) {
                ImGui::TextDisabled("No watchpoints");
            } else {
                if (ImGui::BeginTable("##data_bps", 6,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
                    ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 35.0f);
                    ImGui::TableSetupColumn("Data ID", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                    ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                    ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                    ImGui::TableSetupColumn("##del", ImGuiTableColumnFlags_WidthFixed, 30.0f);
                    ImGui::TableHeadersRow();

                    int to_remove = -1;
                    for (const auto& dbp : dbps) {
                        const char* access_str[] = { "Read", "Write", "RW" };
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn(); ImGui::Text("%d", dbp.id);
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(dbp.data_id.c_str());
                        ImGui::TableNextColumn(); ImGui::Text("0x%04X", dbp.address);
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(dbp.access_type >= 0 && dbp.access_type <= 2
                                               ? access_str[dbp.access_type] : "?");
                        ImGui::TableNextColumn();
                        if (dbp.verified)
                            ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "OK");
                        else
                            ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.2f, 1.0f), "Pend");
                        ImGui::TableNextColumn();
                        char del_label[32];
                        snprintf(del_label, sizeof(del_label), "X##d%d", dbp.id);
                        if (ImGui::SmallButton(del_label)) {
                            to_remove = dbp.id;
                        }
                    }
                    ImGui::EndTable();

                    if (to_remove >= 0) {
                        client.remove_data_breakpoint(to_remove);
                    }
                }
            }
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    ImGui::End();
}
