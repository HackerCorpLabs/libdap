#include "ui_main.h"
#include <imgui.h>
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

    // Controls: scan a range of addresses to discover symbols
    ImGui::Text("Scan address range:");
    ImGui::SetNextItemWidth(100.0f);
    ImGui::InputScalar("Start##sym", ImGuiDataType_U32, &scan_start_, nullptr, nullptr,
                       "0x%04X", ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100.0f);
    ImGui::InputScalar("End##sym", ImGuiDataType_U32, &scan_end_, nullptr, nullptr,
                       "0x%04X", ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    ImGui::BeginDisabled(!stopped);
    if (ImGui::Button("Scan")) {
        // Disassemble the range and extract unique symbols
        if (scan_end_ > scan_start_) {
            int count = (int)(scan_end_ - scan_start_);
            if (count > 2000) count = 2000;
            client.disassemble(scan_start_, count);

            // Extract symbols from disassembly
            symbols_.clear();
            std::set<std::string> seen;
            for (const auto& dl : client.disassembly()) {
                if (!dl.symbol.empty() && seen.find(dl.symbol) == seen.end()) {
                    SymbolEntry se;
                    se.name = dl.symbol;
                    se.address = (uint32_t)strtoul(dl.address.c_str(), nullptr, 0);
                    se.source_path = dl.source_path;
                    se.line = dl.line;
                    symbols_.push_back(se);
                    seen.insert(dl.symbol);
                }
            }

            std::sort(symbols_.begin(), symbols_.end(),
                      [](const SymbolEntry& a, const SymbolEntry& b) {
                          return a.address < b.address;
                      });
        }
    }
    ImGui::EndDisabled();

    // Also harvest symbols from stack frames
    ImGui::SameLine();
    if (ImGui::Button("From Stack")) {
        std::set<std::string> seen;
        for (const auto& s : symbols_) seen.insert(s.name);

        for (const auto& f : client.stack_frames()) {
            if (!f.name.empty() && seen.find(f.name) == seen.end()) {
                SymbolEntry se;
                se.name = f.name;
                se.address = (uint32_t)f.instruction_pointer;
                se.source_path = f.source_path;
                se.line = f.line;
                symbols_.push_back(se);
                seen.insert(f.name);
            }
        }
    }

    ImGui::Separator();

    // Filter
    ImGui::SetNextItemWidth(200.0f);
    ImGui::InputText("Filter", filter_buf_, sizeof(filter_buf_));
    ImGui::SameLine();
    ImGui::Text("%zu symbols", symbols_.size());

    ImGui::Separator();

    // Symbol table
    if (symbols_.empty()) {
        ImGui::TextDisabled("No symbols discovered yet. Use Scan to disassemble a memory range.");
    } else {
        if (ImGui::BeginTable("##symbols", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Sortable)) {
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 150.0f);
            ImGui::TableSetupColumn("Line", ImGuiTableColumnFlags_WidthFixed, 50.0f);
            ImGui::TableHeadersRow();

            std::string filter_lower;
            if (filter_buf_[0]) {
                filter_lower = filter_buf_;
                std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(),
                               [](unsigned char c) { return (char)tolower(c); });
            }

            for (const auto& sym : symbols_) {
                // Filter
                if (!filter_lower.empty()) {
                    std::string name_lower = sym.name;
                    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
                                   [](unsigned char c) { return (char)tolower(c); });
                    if (name_lower.find(filter_lower) == std::string::npos)
                        continue;
                }

                // Highlight current IP symbol
                bool is_current = false;
                if (!client.stack_frames().empty()) {
                    is_current = (sym.address == (uint32_t)client.stack_frames()[0].instruction_pointer);
                }

                ImGui::TableNextRow();
                ImVec4 color = is_current ? ImVec4(1.0f, 1.0f, 0.4f, 1.0f) : ImVec4(0.8f, 0.8f, 0.8f, 1.0f);

                ImGui::TableNextColumn();
                ImGui::TextColored(color, "0x%04X", sym.address);
                ImGui::TableNextColumn();
                ImGui::TextColored(color, "%s", sym.name.c_str());
                ImGui::TableNextColumn();
                if (!sym.source_path.empty())
                    ImGui::TextUnformatted(sym.source_path.c_str());
                ImGui::TableNextColumn();
                if (sym.line > 0)
                    ImGui::Text("%d", sym.line);
            }
            ImGui::EndTable();
        }
    }

    ImGui::End();
}
