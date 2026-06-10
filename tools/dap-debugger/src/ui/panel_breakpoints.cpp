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

    // Auto-populate source field from current stack frame if empty
    if (source_buf_[0] == '\0' && !client.current_source().empty()) {
        snprintf(source_buf_, sizeof(source_buf_), "%s", client.current_source().c_str());
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
            static char addr_text[16] = {};
            ImGui::SetNextItemWidth(120.0f);
            ImGui::InputText("Address##ibp", addr_text, sizeof(addr_text));
            ImGui::SameLine();
            if (ImGui::Button("Add##inst")) {
                uint32_t addr_buf = (uint32_t)strtoul(addr_text, nullptr, 0);
                if (addr_text[0] != '\0') {
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
        // Only show if server supports data breakpoints
        bool has_data_bps = client.has_capability("supportsDataBreakpoints");
        if (has_data_bps && ImGui::BeginTabItem("Watchpoints")) {
            static char data_id_buf[64] = {};
            static int access_type = 1; // write
            static char condition_buf[96] = {};
            ImGui::SetNextItemWidth(120.0f);
            ImGui::InputText("Address/ID", data_id_buf, sizeof(data_id_buf));
            ImGui::SameLine();
            ImGui::SetNextItemWidth(100.0f);
            const char* access_items[] = { "Read", "Write", "ReadWrite" };
            ImGui::Combo("Access", &access_type, access_items, 3);
            ImGui::SameLine();
            if (ImGui::Button("Add##data")) {
                if (strlen(data_id_buf) > 0) {
                    // Condition is meaningful for register watches (Data ID "reg:NAME");
                    // it is sent verbatim — the server owns all condition parsing.
                    client.add_data_breakpoint(data_id_buf, access_type, condition_buf);
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Clear All##data")) {
                client.clear_data_breakpoints();
            }
            // Condition for register watches, e.g. "== 0x50000204", "bit 27 -> 1", "bit 27 changed".
            ImGui::SetNextItemWidth(260.0f);
            ImGui::InputText("Condition", condition_buf, sizeof(condition_buf));
            ImGui::SameLine();
            ImGui::TextDisabled("(?)");
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Register watch: Data ID 'reg:USP' + Condition\n"
                                  "  (empty)        break on any change\n"
                                  "  == 0x50000204  break when equal\n"
                                  "  bit 27 -> 1    break when bit 27 goes 0->1\n"
                                  "  bit 27 changed break when bit 27 toggles");
            }
            // Visual register-watch builder (register dropdown + clickable bit grid).
            if (rw_dialog_ && ImGui::Button("+ Register watch...")) {
                rw_dialog_->open("", -1, "");   // new watch, pick the register in the dialog
            }

            ImGui::Separator();
            const auto& dbps = client.data_breakpoints();
            if (dbps.empty()) {
                ImGui::TextDisabled("No watchpoints");
            } else {
                if (ImGui::BeginTable("##data_bps", 7,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
                    ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 35.0f);
                    ImGui::TableSetupColumn("Data ID", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                    ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                    ImGui::TableSetupColumn("Condition", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                    ImGui::TableSetupColumn("##del", ImGuiTableColumnFlags_WidthFixed, 30.0f);
                    ImGui::TableHeadersRow();

                    int to_remove = -1;
                    for (const auto& dbp : dbps) {
                        const char* access_str[] = { "Read", "Write", "RW" };
                        ImGui::TableNextRow();
                        bool is_reg = dbp.data_id.rfind("reg:", 0) == 0;
                        ImGui::TableNextColumn(); ImGui::Text("%d", dbp.id);
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(dbp.data_id.c_str());
                        ImGui::TableNextColumn();
                        // Register watches have no numeric address — show a dash instead of 0x0000.
                        if (is_reg) ImGui::TextUnformatted("—");
                        else ImGui::Text("0x%04X", dbp.address);
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(dbp.access_type >= 0 && dbp.access_type <= 2
                                               ? access_str[dbp.access_type] : "?");
                        ImGui::TableNextColumn();
                        if (!dbp.condition.empty()) ImGui::TextUnformatted(dbp.condition.c_str());
                        ImGui::TableNextColumn();
                        if (dbp.verified)
                            ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "OK");
                        else
                            ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.2f, 1.0f), "Pend");
                        ImGui::TableNextColumn();
                        // Register watches can be re-built visually via the dialog (Edit =
                        // remove + re-add, since DAP has no in-place edit). Memory watches
                        // just get a delete button.
                        if (is_reg && rw_dialog_) {
                            char edit_label[32];
                            snprintf(edit_label, sizeof(edit_label), "E##e%d", dbp.id);
                            if (ImGui::SmallButton(edit_label)) {
                                rw_dialog_->open(dbp.data_id.substr(4), dbp.id, dbp.condition);
                            }
                            ImGui::SameLine();
                        }
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
