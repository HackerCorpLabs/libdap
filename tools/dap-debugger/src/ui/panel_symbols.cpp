#include "ui_main.h"
#include <imgui.h>
#include <imgui_internal.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <set>

void PanelSymbols::render(DebuggerClient& client)
{
    if (!ImGui::Begin("Symbols")) {
        ImGui::End();
        return;
    }

    if (client.state() == ClientState::Disconnected) {
        ImGui::TextDisabled("Not connected");
        ImGui::End();
        return;
    }

    bool stopped = client.state() == ClientState::Stopped;

    // Primary: DAP symbolList extension
    ImGui::SetNextItemWidth(200.0f);
    ImGui::InputText("Filter", filter_buf_, sizeof(filter_buf_));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.0f);
    const char* type_items[] = { "All", "Functions", "Labels", "Variables" };
    ImGui::Combo("Type", &symbol_type_, type_items, 4);
    ImGui::SameLine();
    ImGui::BeginDisabled(!stopped);
    if (ImGui::Button("Fetch Symbols")) {
        client.fetch_symbols(filter_buf_, symbol_type_);
        use_dap_symbols_ = true;
    }
    ImGui::EndDisabled();

    // Fallback: scan from disassembly
    ImGui::SameLine();
    ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.0f);
    ImGui::InputScalar("Start", ImGuiDataType_U32, &scan_start_, nullptr, nullptr,
                       "%04X", ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.0f);
    ImGui::InputScalar("End", ImGuiDataType_U32, &scan_end_, nullptr, nullptr,
                       "%04X", ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    ImGui::BeginDisabled(!stopped);
    if (ImGui::Button("Scan Disasm")) {
        if (scan_end_ > scan_start_) {
            int count = (int)(scan_end_ - scan_start_);
            if (count > 2000) count = 2000;
            client.disassemble(scan_start_, count);

            scan_symbols_.clear();
            std::set<std::string> seen;
            for (const auto& dl : client.disassembly()) {
                if (!dl.symbol.empty() && seen.find(dl.symbol) == seen.end()) {
                    SymbolEntry se;
                    se.name = dl.symbol;
                    se.address = (uint32_t)strtoul(dl.address.c_str(), nullptr, 0);
                    se.source_path = dl.source_path;
                    se.line = dl.line;
                    scan_symbols_.push_back(se);
                    seen.insert(dl.symbol);
                }
            }
            std::sort(scan_symbols_.begin(), scan_symbols_.end(),
                      [](const SymbolEntry& a, const SymbolEntry& b) {
                          return a.address < b.address;
                      });
            use_dap_symbols_ = false;
        }
    }
    ImGui::EndDisabled();

    // Also harvest from stack
    ImGui::SameLine();
    if (ImGui::Button("+ Stack")) {
        std::set<std::string> seen;
        auto& target = use_dap_symbols_ ? scan_symbols_ : scan_symbols_;
        for (const auto& s : target) seen.insert(s.name);

        for (const auto& f : client.stack_frames()) {
            if (!f.name.empty() && seen.find(f.name) == seen.end()) {
                SymbolEntry se;
                se.name = f.name;
                se.address = (uint32_t)f.instruction_pointer;
                se.source_path = f.source_path;
                se.line = f.line;
                scan_symbols_.push_back(se);
                seen.insert(f.name);
            }
        }
        if (use_dap_symbols_ && scan_symbols_.empty()) {
            use_dap_symbols_ = false;
        }
    }

    ImGui::Separator();

    // Display symbols from whichever source
    const auto& dap_syms = client.symbols();
    bool showing_dap = use_dap_symbols_ && !dap_syms.empty();

    if (showing_dap) {
        ImGui::Text("%zu symbols (from server)", dap_syms.size());
    } else {
        ImGui::Text("%zu symbols (from disassembly scan)", scan_symbols_.size());
    }

    ImGui::Separator();

    // Build filter string
    std::string filter_lower;
    if (filter_buf_[0]) {
        filter_lower = filter_buf_;
        std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(),
                       [](unsigned char c) { return (char)tolower(c); });
    }

    if (ImGui::BeginTable("##symbols", 5,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_Sortable)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Line", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableHeadersRow();

        uint32_t current_ip = 0;
        if (!client.stack_frames().empty())
            current_ip = (uint32_t)client.stack_frames()[0].instruction_pointer;

        if (showing_dap) {
            for (const auto& sym : dap_syms) {
                // Apply filter
                if (!filter_lower.empty()) {
                    std::string name_lower = sym.name;
                    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
                                   [](unsigned char c) { return (char)tolower(c); });
                    if (name_lower.find(filter_lower) == std::string::npos)
                        continue;
                }

                bool is_current = (sym.address == current_ip && current_ip != 0);
                ImVec4 color = is_current ? ImVec4(1.0f, 1.0f, 0.4f, 1.0f) : ImVec4(0.8f, 0.8f, 0.8f, 1.0f);

                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextColored(color, "0x%04X", sym.address);
                ImGui::TableNextColumn(); ImGui::TextColored(color, "%s", sym.name.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(sym.type.c_str());
                ImGui::TableNextColumn();
                if (!sym.source_path.empty()) ImGui::TextUnformatted(sym.source_path.c_str());
                ImGui::TableNextColumn();
                if (sym.line > 0) ImGui::Text("%d", sym.line);
            }
        } else {
            for (const auto& sym : scan_symbols_) {
                if (!filter_lower.empty()) {
                    std::string name_lower = sym.name;
                    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
                                   [](unsigned char c) { return (char)tolower(c); });
                    if (name_lower.find(filter_lower) == std::string::npos)
                        continue;
                }

                bool is_current = (sym.address == current_ip && current_ip != 0);
                ImVec4 color = is_current ? ImVec4(1.0f, 1.0f, 0.4f, 1.0f) : ImVec4(0.8f, 0.8f, 0.8f, 1.0f);

                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextColored(color, "0x%04X", sym.address);
                ImGui::TableNextColumn(); ImGui::TextColored(color, "%s", sym.name.c_str());
                ImGui::TableNextColumn(); ImGui::TextDisabled("--");
                ImGui::TableNextColumn();
                if (!sym.source_path.empty()) ImGui::TextUnformatted(sym.source_path.c_str());
                ImGui::TableNextColumn();
                if (sym.line > 0) ImGui::Text("%d", sym.line);
            }
        }
        ImGui::EndTable();
    }

    ImGui::End();
}
