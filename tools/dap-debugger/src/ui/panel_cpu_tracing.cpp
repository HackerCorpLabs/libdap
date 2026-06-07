// CPU execution trace-ring panel (custom DAP extension, RetroCore).
//
// Drives setCpuTracing / getCpuTraceRing: arm a ring buffer up front, then read
// back the last N retired instructions after a breakpoint/crash. This is the
// supported substitute for reverse execution (the emulator is forward-only).

#include "ui_main.h"
#include <imgui.h>
#include <cstdint>

void PanelCpuTracing::render(DebuggerClient& client)
{
    if (!ImGui::Begin("CPU Trace")) {
        ImGui::End();
        return;
    }

    if (client.state() == ClientState::Disconnected) {
        ImGui::TextDisabled("Not connected");
        last_state_ = client.state();
        ImGui::End();
        return;
    }

    const bool connected = client.state() != ClientState::Disconnected &&
                           client.state() != ClientState::Terminated;
    const bool stopped = client.state() == ClientState::Stopped;

    // --- Tracing controls ------------------------------------------------
    ImGui::Checkbox("Enabled", &enabled_);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.0f);
    ImGui::InputInt("Ring capacity", &ring_capacity_);
    if (ring_capacity_ < 0) ring_capacity_ = 0;

    ImGui::SameLine();
    ImGui::Checkbox("PC filter", &use_filter_);
    ImGui::SameLine();
    ImGui::BeginDisabled(!use_filter_);
    ImGui::SetNextItemWidth(100.0f);
    ImGui::InputScalar("##pcfilter", ImGuiDataType_U32, &pc_filter_, nullptr, nullptr,
                       "%04X", ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(!connected);
    if (ImGui::Button("Apply")) {
        client.set_cpu_tracing(enabled_, ring_capacity_, use_filter_, pc_filter_);
    }
    ImGui::EndDisabled();

    // --- Server-reported status -----------------------------------------
    ImGui::Separator();
    ImGui::Text("Server: tracing %s | ring %s (cap %d) | total instr %llu",
                client.cpu_tracing_enabled() ? "ON" : "off",
                client.cpu_trace_ring_enabled() ? "on" : "off",
                client.cpu_trace_ring_capacity(),
                (unsigned long long)client.cpu_trace_total_instructions());
    if (client.cpu_trace_has_pc_filter()) {
        ImGui::SameLine();
        ImGui::Text("| PC filter 0x%04X", client.cpu_trace_pc_filter());
    }

    // --- Ring read controls ---------------------------------------------
    ImGui::SetNextItemWidth(120.0f);
    ImGui::InputInt("Max entries", &max_entries_);
    if (max_entries_ < 0) max_entries_ = 0;
    ImGui::SameLine();
    ImGui::BeginDisabled(!stopped);
    if (ImGui::Button("Refresh")) {
        client.get_cpu_trace_ring(max_entries_);
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::Checkbox("Auto-refresh on stop", &auto_refresh_);

    // Auto-refresh once on each transition into the Stopped state.
    if (auto_refresh_ && stopped && last_state_ != ClientState::Stopped &&
        client.cpu_trace_ring_enabled()) {
        client.get_cpu_trace_ring(max_entries_);
    }
    last_state_ = client.state();

    // --- Trace entries table --------------------------------------------
    ImGui::Separator();
    const auto& ring = client.cpu_trace_ring();
    ImGui::Text("%zu entries (oldest first)", ring.size());
    if (!client.cpu_trace_header().empty()) {
        ImGui::TextDisabled("%s", client.cpu_trace_header().c_str());
    }

    if (ImGui::BeginTable("##cputrace", 4,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
        ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("PC", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Opcode", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (const auto& e : ring) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("0x%04X", e.pc);
            ImGui::TableNextColumn(); ImGui::Text("0x%02X", e.opcode);
            ImGui::TableNextColumn(); ImGui::TextUnformatted(e.op_code_name.c_str());
            ImGui::TableNextColumn(); ImGui::TextUnformatted(e.text.c_str());
        }
        ImGui::EndTable();
    }

    ImGui::End();
}
