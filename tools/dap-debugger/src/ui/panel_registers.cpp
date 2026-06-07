#include "ui_main.h"
#include <imgui.h>
#include <cstdio>
#include <string>

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

    // Cancel edit if no longer stopped
    bool stopped = client.state() == ClientState::Stopped;
    if (!stopped) editing_var_.clear();
    ImGui::BeginDisabled(!stopped);
    if (ImGui::Button("Refresh")) {
        client.log(ConsoleEntry::Info, "Refreshing variables...");
        client.refresh_stack_trace();
    }
    ImGui::EndDisabled();

    ImGui::Separator();

    // Build lookup of previous values for change highlighting
    const auto& prev = client.prev_scopes();

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

                    // Find matching previous scope for change detection
                    const ScopeInfo* prev_scope = nullptr;
                    for (size_t ps = 0; ps < prev.size(); ps++) {
                        if (prev[ps].name == scope.name) {
                            prev_scope = &prev[ps];
                            break;
                        }
                    }

                    for (size_t vi = 0; vi < scope.variables.size(); vi++) {
                        const auto& v = scope.variables[vi];
                        ImGui::TableNextRow();

                        // Check if value changed from previous stop
                        bool changed = false;
                        if (prev_scope) {
                            for (const auto& pv : prev_scope->variables) {
                                if (pv.name == v.name) {
                                    if (pv.value != v.value) changed = true;
                                    break;
                                }
                            }
                        }

                        ImVec4 val_color = changed ? ImVec4(1.0f, 0.4f, 0.2f, 1.0f)
                                                   : ImVec4(0.8f, 0.8f, 0.8f, 1.0f);

                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(v.name.c_str());

                        // Right-click context menu on variable name
                        char ctx_id[64];
                        snprintf(ctx_id, sizeof(ctx_id), "##regctx_%zu_%zu", s, vi);
                        if (ImGui::BeginPopupContextItem(ctx_id)) {
                            if (ImGui::MenuItem("Copy value")) {
                                ImGui::SetClipboardText(v.value.c_str());
                            }
                            if (ImGui::MenuItem("Add to watches")) {
                                client.add_watch(v.name);
                            }
                            if (stopped && ImGui::MenuItem("Edit value...")) {
                                editing_var_ = v.name;
                                editing_scope_ref_ = scope.variables_reference;
                                snprintf(edit_buf_, sizeof(edit_buf_), "%s", v.value.c_str());
                            }
                            ImGui::EndPopup();
                        }

                        ImGui::TableNextColumn();
                        bool is_editing = (editing_var_ == v.name &&
                                           editing_scope_ref_ == scope.variables_reference);
                        if (is_editing) {
                            ImGui::SetNextItemWidth(-1);
                            char edit_id[64];
                            snprintf(edit_id, sizeof(edit_id), "##edit_%zu_%zu", s, vi);
                            if (ImGui::InputText(edit_id, edit_buf_, sizeof(edit_buf_),
                                                 ImGuiInputTextFlags_EnterReturnsTrue |
                                                 ImGuiInputTextFlags_AutoSelectAll)) {
                                client.set_variable(scope.variables_reference, v.name, edit_buf_);
                                editing_var_.clear();
                            }
                            // Cancel on Escape or click elsewhere
                            if (ImGui::IsKeyPressed(ImGuiKey_Escape) ||
                                (!ImGui::IsItemActive() && !ImGui::IsItemFocused() &&
                                 ImGui::IsMouseClicked(0))) {
                                editing_var_.clear();
                            }
                        } else {
                            // Clickable value -- single click to edit
                            char val_id[64];
                            snprintf(val_id, sizeof(val_id), "##val_%zu_%zu", s, vi);
                            std::string val_display = v.value;
                            if (changed) val_display += " *";
                            ImGui::PushStyleColor(ImGuiCol_Text, val_color);
                            if (ImGui::Selectable((val_display + val_id).c_str()) && stopped) {
                                editing_var_ = v.name;
                                editing_scope_ref_ = scope.variables_reference;
                                snprintf(edit_buf_, sizeof(edit_buf_), "%s", v.value.c_str());
                            }
                            ImGui::PopStyleColor();
                        }

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
