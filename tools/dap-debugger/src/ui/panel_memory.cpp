// Memory panel for the dap-debugger GUI.
//
// Provides a hex/ASCII view that can read either the virtual address
// space or the physical address space (via the libdap "phys:" prefix on
// memoryReference). Required for inspecting kernel data on split I/D
// kernels where data lives at physical clicks above 64K and is not
// reachable through the current PT mapping.

#include "ui_main.h"
#include <imgui.h>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

// Minimal base64 decoder shared with the rest of the GUI; the panel only
// needs to convert the server response into raw bytes for hex display.
static int b64_decode(const char *input, unsigned char *out, int max_out)
{
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int in_len = (int)strlen(input);
    int out_len = 0;
    for (int i = 0; i + 3 < in_len && out_len + 3 <= max_out; i += 4) {
        int v[4] = {0,0,0,0};
        int valid = 0;
        for (int j = 0; j < 4; j++) {
            char c = input[i+j];
            if (c == '=') v[j] = 0;
            else { const char *p = strchr(tab, c); if (p) { v[j] = (int)(p-tab); valid++; } }
        }
        if (valid >= 2) out[out_len++] = (unsigned char)((v[0] << 2) | (v[1] >> 4));
        if (valid >= 3) out[out_len++] = (unsigned char)(((v[1] & 0xF) << 4) | (v[2] >> 2));
        if (valid >= 4) out[out_len++] = (unsigned char)(((v[2] & 0x3) << 6) | v[3]);
    }
    return out_len;
}

static int b64_encode_into(const unsigned char *in, int in_len, char *out, int max_out)
{
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int o = 0;
    for (int i = 0; i < in_len; i += 3) {
        int b0 = in[i];
        int b1 = (i+1 < in_len) ? in[i+1] : 0;
        int b2 = (i+2 < in_len) ? in[i+2] : 0;
        if (o + 4 > max_out) break;
        out[o++] = tab[b0 >> 2];
        out[o++] = tab[((b0 & 0x3) << 4) | (b1 >> 4)];
        out[o++] = (i+1 < in_len) ? tab[((b1 & 0xF) << 2) | (b2 >> 6)] : '=';
        out[o++] = (i+2 < in_len) ? tab[b2 & 0x3F] : '=';
    }
    if (o < max_out) out[o] = 0;
    return o;
}

} // namespace

void PanelMemory::render(DebuggerClient& client)
{
    if (!ImGui::Begin("Memory")) { ImGui::End(); return; }

    ImGui::Text("Address space:");
    ImGui::SameLine();
    ImGui::RadioButton("Virtual", &address_space_, 0); ImGui::SameLine();
    ImGui::RadioButton("Physical", &address_space_, 1); ImGui::SameLine();
    ImGui::RadioButton("I-space", &address_space_, 2); ImGui::SameLine();
    ImGui::RadioButton("D-space", &address_space_, 3);

    ImGui::PushItemWidth(140);
    ImGui::InputText("Address (hex)", addr_buf_, sizeof(addr_buf_),
                     ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    ImGui::InputInt("Bytes", &count_);
    ImGui::PopItemWidth();
    if (count_ < 1) count_ = 1;
    if (count_ > 4096) count_ = 4096;

    if (ImGui::Button("Read")) {
        uint32_t addr = (uint32_t)strtoul(addr_buf_, nullptr, 16);
        DebuggerClient::AddressSpace as = DebuggerClient::AddressSpace::Virtual;
        if (address_space_ == 1) as = DebuggerClient::AddressSpace::Physical;
        else if (address_space_ == 2) as = DebuggerClient::AddressSpace::ISpace;
        else if (address_space_ == 3) as = DebuggerClient::AddressSpace::DSpace;
        std::string b64 = client.read_memory(addr, 0, (size_t)count_, as);
        if (!b64.empty()) {
            unsigned char raw[4096];
            int n = b64_decode(b64.c_str(), raw, (int)sizeof(raw));
            data_.assign(raw, raw + n);
            last_addr_ = addr;
            last_space_ = address_space_;
        } else {
            data_.clear();
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Write hex")) {
        // Parse write_hex_buf_ as a sequence of hex bytes (whitespace ok)
        unsigned char buf[4096];
        int n = 0;
        const char *p = write_hex_buf_;
        while (*p && n < (int)sizeof(buf)) {
            while (*p == ' ' || *p == '\t' || *p == ',') p++;
            if (!*p) break;
            unsigned int byte = 0;
            if (sscanf(p, "%2x", &byte) != 1) break;
            buf[n++] = (unsigned char)byte;
            p += 2;
        }
        if (n > 0) {
            char b64[8192];
            b64_encode_into(buf, n, b64, sizeof(b64));
            uint32_t addr = (uint32_t)strtoul(addr_buf_, nullptr, 16);
            DebuggerClient::AddressSpace as = (address_space_ == 1)
                ? DebuggerClient::AddressSpace::Physical
                : DebuggerClient::AddressSpace::Virtual;
            client.write_memory(addr, 0, std::string(b64), as);
        }
    }

    ImGui::PushItemWidth(-1);
    ImGui::InputText("##writehex", write_hex_buf_, sizeof(write_hex_buf_));
    ImGui::PopItemWidth();
    ImGui::TextDisabled("Bytes to write (hex, e.g. 'd1 00 00 00')");

    ImGui::Separator();

    if (!data_.empty()) {
        ImGui::Text("Read %zu bytes from %s 0x%X",
                    data_.size(),
                    last_space_ == 1 ? "physical" : "virtual",
                    last_addr_);
        ImGui::BeginChild("hexview", ImVec2(0, 0), true);
        const int row_size = 16;
        for (size_t row = 0; row < data_.size(); row += row_size) {
            char line[128];
            int pos = snprintf(line, sizeof(line), "%06X  ", (unsigned)(last_addr_ + row));
            for (int c = 0; c < row_size; c++) {
                if (row + c < data_.size())
                    pos += snprintf(line+pos, sizeof(line)-pos, "%02X ", data_[row+c]);
                else
                    pos += snprintf(line+pos, sizeof(line)-pos, "   ");
            }
            pos += snprintf(line+pos, sizeof(line)-pos, " ");
            for (int c = 0; c < row_size && row + c < data_.size(); c++) {
                unsigned char b = data_[row+c];
                line[pos++] = (b >= 32 && b < 127) ? (char)b : '.';
            }
            line[pos] = 0;
            ImGui::TextUnformatted(line);
        }
        ImGui::EndChild();
    } else {
        ImGui::TextDisabled("No data. Enter an address and click Read.");
    }

    ImGui::End();
}
