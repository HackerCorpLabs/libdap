#include "ui_main.h"
#include <imgui.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>

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
                            ImGui::Separator();
                            // Register watches (reg:NAME data breakpoints). "Break on change"
                            // is the one-click any-change watch; "Register watch…" opens the
                            // visual dialog (value / bit grid). The condition is parsed
                            // server-side (single source of truth).
                            if (ImGui::MenuItem("Break on change")) {
                                client.add_data_breakpoint("reg:" + v.name, 1 /*write*/, "");
                            }
                            if (rw_dialog_ && ImGui::MenuItem("Register watch...")) {
                                rw_dialog_->open(v.name, -1, "");   // new watch, pre-targeted
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

// ── RegisterWatchDialog ─────────────────────────────────────────────────────
// Visual builder for a register watch. Reuses the live Registers scope (for the
// dropdown + bit grid) and DebuggerClient::add_data_breakpoint (the single submit path).
// All it ever emits is reg:NAME + a condition string; the server parses the condition.

namespace {

// Parse a register's bit width from its DAP type string (e.g. "32-bit" -> 32). Falls back to 32.
static int rw_parse_width(const std::string& type)
{
    int w = 0;
    for (size_t i = 0; i < type.size() && type[i] >= '0' && type[i] <= '9'; ++i)
        w = w * 10 + (type[i] - '0');
    if (w == 8 || w == 16 || w == 32 || w == 64) return w;
    return 32;
}

// Look up a register's current value + width from the live "Registers" scope.
// Returns false when the register isn't present (e.g. not connected / not stopped).
static bool rw_lookup_register(DebuggerClient& client, const std::string& name,
                               uint64_t& value, int& width)
{
    const std::vector<ScopeInfo>& scopes = client.scopes();
    for (size_t s = 0; s < scopes.size(); ++s) {
        for (size_t v = 0; v < scopes[s].variables.size(); ++v) {
            const VariableInfo& var = scopes[s].variables[v];
            if (var.name == name) {
                value = (uint64_t)strtoull(var.value.c_str(), nullptr, 0);  // "0x.." or decimal
                width = rw_parse_width(var.type);
                return true;
            }
        }
    }
    return false;
}

// Operator labels — index matches op_ and the strings the server's grammar accepts.
static const char* const RW_OPS[] = { "==", "!=", "<", ">", "<=", ">=" };

} // namespace

void RegisterWatchDialog::open(const std::string& target_reg, int edit_id,
                               const std::string& existing_condition)
{
    target_reg_ = target_reg;
    edit_id_ = edit_id;
    // Reset to sensible defaults, then prefill from the existing condition when editing.
    mode_ = 0;
    op_ = 0;
    value_buf_[0] = '\0';
    mask_buf_[0] = '\0';
    bit_index_ = 0;
    bit_mode_ = 0;
    if (!existing_condition.empty()) load_from_condition(existing_condition);
    open_request_ = true;
}

// Reverse-parse a condition string into the dialog fields (best-effort, mirrors build_condition).
void RegisterWatchDialog::load_from_condition(const std::string& condition)
{
    std::string c = condition;
    // trim leading spaces
    size_t b = c.find_first_not_of(" \t");
    if (b == std::string::npos) { mode_ = 0; return; }
    c = c.substr(b);

    if (c.rfind("bit", 0) == 0) {
        mode_ = 2;
        // "bit N -> 1" | "bit N -> 0" | "bit N changed"
        int n = 0; size_t i = 3;
        while (i < c.size() && (c[i] == ' ')) ++i;
        while (i < c.size() && c[i] >= '0' && c[i] <= '9') { n = n * 10 + (c[i] - '0'); ++i; }
        bit_index_ = n;
        if (c.find("changed") != std::string::npos) bit_mode_ = 2;
        else if (c.find("-> 0") != std::string::npos || c.find("->0") != std::string::npos) bit_mode_ = 1;
        else bit_mode_ = 0;
        return;
    }

    mode_ = 1;  // value
    // optional "& MASK" prefix
    if (c[0] == '&') {
        size_t oppos = c.find_first_of("=!<>", 1);
        std::string m = c.substr(1, (oppos == std::string::npos ? c.size() : oppos) - 1);
        // trim
        size_t mb = m.find_first_not_of(" \t"); size_t me = m.find_last_not_of(" \t");
        if (mb != std::string::npos) snprintf(mask_buf_, sizeof(mask_buf_), "%s", m.substr(mb, me - mb + 1).c_str());
        c = (oppos == std::string::npos) ? "" : c.substr(oppos);
    }
    // operator
    for (int i = 0; i < 6; ++i) {
        if (c.rfind(RW_OPS[i], 0) == 0) {
            // prefer two-char ops first by checking longer matches — RW_OPS ordering already
            // lists "==","!=" before "<",">", but "<=",">=" must beat "<",">":
            op_ = i;
            break;
        }
    }
    // Re-scan for the longer "<=" / ">=" so they aren't shadowed by "<" / ">".
    if (c.rfind("<=", 0) == 0) op_ = 4;
    else if (c.rfind(">=", 0) == 0) op_ = 5;
    size_t oplen = (op_ == 0 || op_ == 1 || op_ == 4 || op_ == 5) ? 2 : 1;
    std::string val = c.size() >= oplen ? c.substr(oplen) : "";
    size_t vb = val.find_first_not_of(" \t");
    if (vb != std::string::npos) snprintf(value_buf_, sizeof(value_buf_), "%s", val.substr(vb).c_str());
}

// Build the condition string the dialog currently represents (matches the server grammar).
std::string RegisterWatchDialog::build_condition() const
{
    if (mode_ == 0) return "";   // any change

    if (mode_ == 2) {            // bit
        char buf[40];
        const char* tail = (bit_mode_ == 0) ? "-> 1" : (bit_mode_ == 1) ? "-> 0" : "changed";
        snprintf(buf, sizeof(buf), "bit %d %s", bit_index_, tail);
        return std::string(buf);
    }

    // value: [& MASK] OP VALUE
    std::string cond;
    if (mask_buf_[0] != '\0') { cond += "& "; cond += mask_buf_; cond += " "; }
    cond += RW_OPS[op_];
    cond += " ";
    cond += value_buf_;
    return cond;
}

void RegisterWatchDialog::render(DebuggerClient& client)
{
    if (open_request_) { ImGui::OpenPopup("Register watch##rwd"); open_request_ = false; }

    // Center the modal.
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (!ImGui::BeginPopupModal("Register watch##rwd", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
        return;

    // ── Register selector ───────────────────────────────────────────────
    // Editing keeps the register fixed; a new watch lets the user pick from the live list.
    if (edit_id_ >= 0) {
        ImGui::Text("Register: reg:%s   (editing watch #%d)", target_reg_.c_str(), edit_id_);
    } else {
        if (ImGui::BeginCombo("Register", target_reg_.empty() ? "(select)" : target_reg_.c_str())) {
            const std::vector<ScopeInfo>& scopes = client.scopes();
            for (size_t s = 0; s < scopes.size(); ++s) {
                for (size_t v = 0; v < scopes[s].variables.size(); ++v) {
                    const std::string& nm = scopes[s].variables[v].name;
                    bool sel = (nm == target_reg_);
                    if (ImGui::Selectable(nm.c_str(), sel)) target_reg_ = nm;
                    if (sel) ImGui::SetItemDefaultFocus();
                }
            }
            ImGui::EndCombo();
        }
    }

    // Live value + width of the selected register (for the bit grid + preview).
    uint64_t cur_value = 0;
    int width = 32;
    bool have_reg = !target_reg_.empty() && rw_lookup_register(client, target_reg_, cur_value, width);

    ImGui::Separator();

    // ── Mode ─────────────────────────────────────────────────────────────
    ImGui::TextUnformatted("Break when the register:");
    ImGui::RadioButton("changes (any)", &mode_, 0); ImGui::SameLine();
    ImGui::RadioButton("matches a value", &mode_, 1); ImGui::SameLine();
    ImGui::RadioButton("has a bit condition", &mode_, 2);

    ImGui::Separator();

    if (mode_ == 1) {
        // Value editor: [& mask] OP value
        ImGui::SetNextItemWidth(70.0f);
        ImGui::Combo("op", &op_, RW_OPS, IM_ARRAYSIZE(RW_OPS));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(160.0f);
        ImGui::InputText("value", value_buf_, sizeof(value_buf_));
        ImGui::SetNextItemWidth(160.0f);
        ImGui::InputText("mask (optional)", mask_buf_, sizeof(mask_buf_));
        ImGui::TextDisabled("value/mask accept 0x hex or decimal, e.g. 0x50000204");
    } else if (mode_ == 2) {
        // Bit grid: clickable buttons, MSB..LSB, highlighting set bits of the live value.
        ImGui::Text("Bit (target = %d):", bit_index_);
        if (have_reg) {
            ImGui::TextDisabled("current value 0x%llX  (green = set; click to pick target bit)",
                                (unsigned long long)cur_value);
        } else {
            ImGui::TextDisabled("(register value unavailable — connect & pause to see live bits)");
        }
        // Render width bits, 8 per row, high bit first.
        for (int row = 0; row * 8 < width; ++row) {
            for (int col = 0; col < 8; ++col) {
                int bit = width - 1 - (row * 8 + col);
                if (bit < 0) break;
                bool set = have_reg && ((cur_value >> bit) & 1ULL) != 0;
                bool target = (bit == bit_index_);
                char lbl[24];
                snprintf(lbl, sizeof(lbl), "%d##bit%d", bit, bit);
                // Colour: target = blue, set = green, clear = default.
                int pushed = 0;
                if (target) { ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.20f, 0.45f, 0.85f, 1.0f)); pushed = 1; }
                else if (set) { ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.20f, 0.55f, 0.25f, 1.0f)); pushed = 1; }
                if (ImGui::Button(lbl, ImVec2(34, 0))) bit_index_ = bit;
                if (pushed) ImGui::PopStyleColor();
                if (col < 7 && bit > 0) ImGui::SameLine();
            }
        }
        ImGui::RadioButton("-> 1 (rises)", &bit_mode_, 0); ImGui::SameLine();
        ImGui::RadioButton("-> 0 (falls)", &bit_mode_, 1); ImGui::SameLine();
        ImGui::RadioButton("changed", &bit_mode_, 2);
    }

    // ── Live preview of exactly what will be sent ────────────────────────
    ImGui::Separator();
    std::string cond = build_condition();
    ImGui::Text("Will arm:  reg:%s  %s",
                target_reg_.empty() ? "?" : target_reg_.c_str(),
                cond.empty() ? "(any change)" : cond.c_str());

    // ── Actions ──────────────────────────────────────────────────────────
    bool can_set = !target_reg_.empty();
    if (!can_set) ImGui::BeginDisabled();
    if (ImGui::Button(edit_id_ >= 0 ? "Update" : "Set")) {
        // Editing = remove the old entry then add the rebuilt one (DAP has no in-place edit;
        // both go through the replace-all setDataBreakpoints inside the client).
        if (edit_id_ >= 0) client.remove_data_breakpoint(edit_id_);
        client.add_data_breakpoint("reg:" + target_reg_, 1 /*write*/, cond);
        ImGui::CloseCurrentPopup();
    }
    if (!can_set) ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();

    ImGui::EndPopup();
}
