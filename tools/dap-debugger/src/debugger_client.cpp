#include "debugger_client.h"
#include "dap_wrapper.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <algorithm>

struct DebuggerClient::Impl {
    DAPClient* client = nullptr;

};

DebuggerClient::DebuggerClient()
    : impl_(new Impl)
{
}

DebuggerClient::~DebuggerClient()
{
    if (impl_->client) {
        dap_client_free(impl_->client);
    }
    delete impl_;
}

void DebuggerClient::log(ConsoleEntry::Category cat, const std::string& text)
{
    console_log_.push_back({cat, text});
    if (debug_) {
        fprintf(stderr, "[%d] %s\n", (int)cat, text.c_str());
    }
}

void DebuggerClient::log_protocol(ProtocolEntry::Direction dir, const std::string& json)
{
    // Cap at 10000 entries to avoid unbounded growth
    if (protocol_log_.size() > 10000) {
        protocol_log_.erase(protocol_log_.begin(), protocol_log_.begin() + 5000);
    }
    protocol_log_.push_back({dir, json});
}

void DebuggerClient::log_protocol_sent(const char* command, void* args_json)
{
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "type", "request");
    cJSON_AddStringToObject(obj, "command", command);
    if (args_json) {
        cJSON_AddItemToObject(obj, "arguments", cJSON_Duplicate((cJSON*)args_json, 1));
    }
    char* str = cJSON_Print(obj);
    if (str) {
        log_protocol(ProtocolEntry::Sent, str);
        free(str);
    }
    cJSON_Delete(obj);
}

void DebuggerClient::log_protocol_received(void* message_json)
{
    char* str = cJSON_Print((cJSON*)message_json);
    if (str) {
        log_protocol(ProtocolEntry::Received, str);
        free(str);
    }
}

// ---------------------------------------------------------------------------
// Connection lifecycle
// ---------------------------------------------------------------------------

void DebuggerClient::connect(const std::string& host, int port)
{
    if (impl_->client) {
        dap_client_free(impl_->client);
        impl_->client = nullptr;
    }

    impl_->client = dap_client_create(host.c_str(), port);
    if (!impl_->client) {
        log(ConsoleEntry::Error, "Failed to create DAP client");
        state_ = ClientState::Disconnected;
        return;
    }

    impl_->client->debug_mode = debug_;

    // Enable transport debug logging so raw JSON is captured
    if (impl_->client->transport) {
        impl_->client->transport->debuglog = debug_;
    }

    int rc = dap_client_connect(impl_->client);
    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Error, std::string("Connect failed: ") + dap_error_message((DAPError)rc));
        dap_client_free(impl_->client);
        impl_->client = nullptr;
        state_ = ClientState::Disconnected;
        return;
    }

    state_ = ClientState::Connected;
    log(ConsoleEntry::Info, "Connected to " + host + ":" + std::to_string(port));
}

static void parse_capabilities(cJSON* obj, std::vector<ServerCapability>& caps)
{
    caps.clear();
    if (!obj) return;

    // If obj has a "body" child, use that instead (handles full response envelope)
    cJSON* body = cJSON_GetObjectItem(obj, "body");
    cJSON* source = body ? body : obj;

    cJSON* item = source->child;
    while (item) {
        if (cJSON_IsBool(item) && item->string) {
            // Skip non-capability fields that happen to be boolean
            if (strcmp(item->string, "success") != 0) {
                ServerCapability sc;
                sc.name = item->string;
                sc.supported = cJSON_IsTrue(item);
                caps.push_back(sc);
            }
        }
        item = item->next;
    }
}

void DebuggerClient::initialize()
{
    if (!impl_->client || state_ != ClientState::Connected) return;

    log_protocol_sent("initialize", nullptr);

    // Use send_request directly so we can capture the response body for
    // capabilities and protocol logging. dap_client_initialize() consumes
    // the response internally and we never see it.
    cJSON* init_args = cJSON_CreateObject();
    cJSON_AddStringToObject(init_args, "clientID", "dap-gui-debugger");
    cJSON_AddStringToObject(init_args, "clientName", "DAP GUI Debugger");
    cJSON_AddStringToObject(init_args, "adapterID", "nd100x");
    cJSON_AddStringToObject(init_args, "pathFormat", "path");
    cJSON_AddBoolToObject(init_args, "linesStartAt1", 1);
    cJSON_AddBoolToObject(init_args, "columnsStartAt1", 1);
    cJSON_AddBoolToObject(init_args, "supportsVariableType", 1);
    cJSON_AddBoolToObject(init_args, "supportsRunInTerminalRequest", 0);
    cJSON_AddBoolToObject(init_args, "supportsMemoryReferences", 1);
    cJSON_AddBoolToObject(init_args, "supportsInvalidatedEvent", 1);
    cJSON_AddBoolToObject(init_args, "supportsMemoryEvent", 1);

    char* resp_body = nullptr;
    int rc = dap_client_send_request(impl_->client, DAP_CMD_INITIALIZE, init_args, &resp_body);
    cJSON_Delete(init_args);

    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Warning, "Initialize response timeout (continuing anyway)");
    } else if (resp_body) {
        // Log the full response
        log_protocol(ProtocolEntry::Received, resp_body);

        cJSON* resp = cJSON_Parse(resp_body);
        if (resp) {
            parse_capabilities(resp, server_capabilities_);
            log(ConsoleEntry::Info, "Server capabilities: " +
                std::to_string(server_capabilities_.size()) + " entries");
            cJSON_Delete(resp);
        }
    }
    free(resp_body);

    state_ = ClientState::Initialized;
    log(ConsoleEntry::Info, "Session initialized");

    // Get initial thread list (like the console debugger does)
    refresh_threads();
}

void DebuggerClient::launch(const std::string& program)
{
    LaunchArgs args;
    args.program = program;
    args.stop_on_entry = true;
    launch(args);
}

void DebuggerClient::launch(const LaunchArgs& largs)
{
    if (!impl_->client || state_ != ClientState::Initialized) return;

    // Send launch request asynchronously (fire-and-forget), matching the
    // console debugger pattern. The server will respond with events
    // (process, stopped) which we handle in poll().
    cJSON* request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "type", "request");
    cJSON_AddNumberToObject(request, "seq", impl_->client->seq++);
    cJSON_AddStringToObject(request, "command", "launch");

    cJSON* args = cJSON_CreateObject();

    // Core DAP fields
    cJSON_AddStringToObject(args, "request", "launch");

    // Program path (required)
    if (!largs.program.empty()) {
        cJSON_AddStringToObject(args, "program", largs.program.c_str());
    }

    // Source file
    if (!largs.source_file.empty()) {
        cJSON_AddStringToObject(args, "sourceFile", largs.source_file.c_str());
    }

    // Map file
    if (!largs.map_file.empty()) {
        cJSON_AddStringToObject(args, "mapFile", largs.map_file.c_str());
    }

    // Working directory
    if (!largs.cwd.empty()) {
        cJSON_AddStringToObject(args, "cwd", largs.cwd.c_str());
    }

    // Launch options
    cJSON_AddBoolToObject(args, "stopOnEntry", largs.stop_on_entry);
    cJSON_AddBoolToObject(args, "noDebug", false);

    // Configuration identification
    cJSON_AddStringToObject(args, "name", "GUI Debug Session");
    cJSON_AddStringToObject(args, "type", "nd100");

    cJSON_AddItemToObject(request, "arguments", args);

    log_protocol_sent("launch", args);

    char* msg_str = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);

    if (msg_str) {
        int rc = dap_transport_send(impl_->client->transport, msg_str);
        free(msg_str);
        if (rc != 0) {
            log(ConsoleEntry::Error, "Failed to send launch request");
            return;
        }
    }

    // Send configurationDone (also async)
    cJSON* cfg_req = cJSON_CreateObject();
    cJSON_AddStringToObject(cfg_req, "type", "request");
    cJSON_AddNumberToObject(cfg_req, "seq", impl_->client->seq++);
    cJSON_AddStringToObject(cfg_req, "command", "configurationDone");

    log_protocol_sent("configurationDone", nullptr);

    msg_str = cJSON_PrintUnformatted(cfg_req);
    cJSON_Delete(cfg_req);

    if (msg_str) {
        dap_transport_send(impl_->client->transport, msg_str);
        free(msg_str);
    }

    // Don't set state to Stopped here -- let the stopped event do that
    // via poll(). The server will send process + stopped events.
    state_ = ClientState::Running;
    log(ConsoleEntry::Info, "Launch sent: " + largs.program);
}

void DebuggerClient::disconnect()
{
    if (!impl_->client) return;

    DAPDisconnectResult result = {};
    dap_client_disconnect(impl_->client, false, true, &result);
    dap_client_free(impl_->client);
    impl_->client = nullptr;

    state_ = ClientState::Disconnected;
    stack_frames_.clear();
    scopes_.clear();
    variables_.clear();
    breakpoints_.clear();
    instruction_breakpoints_.clear();
    data_breakpoints_.clear();
    disassembly_.clear();
    threads_.clear();
    modules_.clear();
    process_name_.clear();
    process_id_ = 0;
    stop_reason_.clear();
    hit_breakpoint_ids_.clear();
    log(ConsoleEntry::Info, "Disconnected");
}

void DebuggerClient::force_close()
{
    if (!impl_->client) return;

    // Close the socket directly without trying to send a disconnect request
    if (impl_->client->transport) {
        dap_transport_stop(impl_->client->transport);
    }
    impl_->client->connected = false;
    dap_client_free(impl_->client);
    impl_->client = nullptr;
    state_ = ClientState::Disconnected;
}

// ---------------------------------------------------------------------------
// Execution control
// ---------------------------------------------------------------------------

// Helper: send a DAP request asynchronously via transport (no blocking wait)
static bool send_async_request(DAPClient* client, const char* command, cJSON* args,
                               DebuggerClient* self)
{
    cJSON* request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "type", "request");
    cJSON_AddNumberToObject(request, "seq", client->seq++);
    cJSON_AddStringToObject(request, "command", command);
    if (args) {
        cJSON_AddItemToObject(request, "arguments", args);
    }

    char* msg_str = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);

    if (!msg_str) return false;

    int rc = dap_transport_send(client->transport, msg_str);
    free(msg_str);

    return rc == 0;
}

void DebuggerClient::do_continue()
{
    if (!impl_->client) return;
    if (state_ != ClientState::Stopped && state_ != ClientState::Initialized) return;

    cJSON* args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "threadId", thread_id_);
    cJSON_AddBoolToObject(args, "singleThread", false);

    log_protocol_sent("continue", args);

    if (!send_async_request(impl_->client, "continue", args, this)) {
        log(ConsoleEntry::Error, "Failed to send continue request");
        return;
    }
    state_ = ClientState::Running;
    log(ConsoleEntry::Info, "Continuing...");
}

void DebuggerClient::step_over()
{
    if (!impl_->client || state_ != ClientState::Stopped) return;

    cJSON* args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "threadId", thread_id_);

    log_protocol_sent("next", args);

    if (!send_async_request(impl_->client, "next", args, this)) {
        log(ConsoleEntry::Error, "Failed to send step over request");
        return;
    }
    state_ = ClientState::Running;
    log(ConsoleEntry::Info, "Stepping over...");
}

void DebuggerClient::step_in()
{
    if (!impl_->client || state_ != ClientState::Stopped) return;

    cJSON* args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "threadId", thread_id_);

    log_protocol_sent("stepIn", args);

    if (!send_async_request(impl_->client, "stepIn", args, this)) {
        log(ConsoleEntry::Error, "Failed to send step in request");
        return;
    }
    state_ = ClientState::Running;
    log(ConsoleEntry::Info, "Stepping in...");
}

void DebuggerClient::step_out()
{
    if (!impl_->client || state_ != ClientState::Stopped) return;

    cJSON* args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "threadId", thread_id_);

    log_protocol_sent("stepOut", args);

    if (!send_async_request(impl_->client, "stepOut", args, this)) {
        log(ConsoleEntry::Error, "Failed to send step out request");
        return;
    }
    state_ = ClientState::Running;
    log(ConsoleEntry::Info, "Stepping out...");
}

void DebuggerClient::step_back()
{
    if (!impl_->client || state_ != ClientState::Stopped) return;

    cJSON* args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "threadId", thread_id_);

    log_protocol_sent("stepBack", args);

    if (!send_async_request(impl_->client, "stepBack", args, this)) {
        log(ConsoleEntry::Error, "Failed to send step back request");
        return;
    }
    state_ = ClientState::Running;
    log(ConsoleEntry::Info, "Stepping back...");
}

void DebuggerClient::pause()
{
    if (!impl_->client || state_ != ClientState::Running) return;

    cJSON* args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "threadId", thread_id_);

    log_protocol_sent("pause", args);

    if (!send_async_request(impl_->client, "pause", args, this)) {
        log(ConsoleEntry::Error, "Failed to send pause request");
        return;
    }
    log(ConsoleEntry::Info, "Pause requested");
}

// ---------------------------------------------------------------------------
// Data queries
// ---------------------------------------------------------------------------

void DebuggerClient::refresh_stack_trace()
{
    if (!impl_->client) return;

    DAPStackFrame* frames = nullptr;
    int count = 0;
    int rc = dap_client_get_stack_trace(impl_->client, thread_id_, &frames, &count);
    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Warning, "Failed to get stack trace");
        return;
    }

    stack_frames_.clear();
    for (int i = 0; i < count; i++) {
        StackFrameInfo fi;
        fi.id = frames[i].id;
        fi.name = frames[i].name ? frames[i].name : "";
        fi.source_path = frames[i].source_path ? frames[i].source_path : "";
        fi.source_name = frames[i].source_name ? frames[i].source_name : "";
        fi.line = frames[i].line;
        fi.instruction_pointer = frames[i].instruction_pointer_reference;
        stack_frames_.push_back(fi);
    }

    if (count > 0) {
        current_source_ = stack_frames_[0].source_path;
        refresh_scopes(stack_frames_[0].id);
    }

    free(frames);
}

void DebuggerClient::refresh_scopes(int frame_id)
{
    if (!impl_->client) return;

    DAPGetScopesResult result = {};
    int rc = dap_client_get_scopes(impl_->client, frame_id, &result);
    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Warning, "Failed to get scopes");
        return;
    }

    scopes_.clear();
    variables_.clear();

    for (size_t i = 0; i < result.num_scopes; i++) {
        ScopeInfo si;
        si.name = result.scopes[i].name ? result.scopes[i].name : "";
        si.variables_reference = result.scopes[i].variables_reference;

        DAPGetVariablesResult vresult = {};
        rc = dap_client_get_variables(impl_->client, result.scopes[i].variables_reference, 0, 0, &vresult);
        if (rc == DAP_ERROR_NONE) {
            for (size_t j = 0; j < vresult.num_variables; j++) {
                VariableInfo vi;
                vi.name = vresult.variables[j].name ? vresult.variables[j].name : "";
                vi.value = vresult.variables[j].value ? vresult.variables[j].value : "";
                vi.type = vresult.variables[j].type ? vresult.variables[j].type : "";
                vi.variables_reference = vresult.variables[j].variables_reference;
                si.variables.push_back(vi);
                variables_.push_back(vi);
            }
            dap_get_variables_result_free(&vresult);
        }

        scopes_.push_back(si);
    }

    dap_get_scopes_result_free(&result);
}

void DebuggerClient::refresh_variables(int frame_id)
{
    refresh_scopes(frame_id);
}

// ---------------------------------------------------------------------------
// Source breakpoints
// ---------------------------------------------------------------------------

void DebuggerClient::sync_source_breakpoints(const std::string& source)
{
    // Collect all breakpoints for this source file
    std::vector<DAPSourceBreakpoint> sbps;
    for (const auto& bp : breakpoints_) {
        if (bp.source_path == source) {
            DAPSourceBreakpoint s = {};
            s.line = bp.line;
            s.condition = bp.condition.empty() ? nullptr : const_cast<char*>(bp.condition.c_str());
            s.hit_condition = bp.hit_condition.empty() ? nullptr : const_cast<char*>(bp.hit_condition.c_str());
            s.log_message = bp.log_message.empty() ? nullptr : const_cast<char*>(bp.log_message.c_str());
            sbps.push_back(s);
        }
    }

    DAPSetBreakpointsResult result = {};
    int rc = dap_client_set_breakpoints(impl_->client, source.c_str(),
                                        sbps.empty() ? nullptr : sbps.data(),
                                        (int)sbps.size(), &result);
    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Error, "Failed to sync breakpoints for " + source);
        return;
    }

    // Remove old entries for this source and replace with server response
    breakpoints_.erase(
        std::remove_if(breakpoints_.begin(), breakpoints_.end(),
                        [&source](const BreakpointInfo& b) { return b.source_path == source; }),
        breakpoints_.end());

    for (size_t i = 0; i < result.num_breakpoints; i++) {
        BreakpointInfo bi;
        bi.id = result.breakpoints[i].id;
        bi.verified = result.breakpoints[i].verified;
        bi.source_path = result.breakpoints[i].source_path ? result.breakpoints[i].source_path : source;
        bi.line = result.breakpoints[i].line;
        bi.instruction_reference = result.breakpoints[i].instruction_reference;
        bi.condition = result.breakpoints[i].condition ? result.breakpoints[i].condition : "";
        bi.hit_condition = result.breakpoints[i].hit_condition ? result.breakpoints[i].hit_condition : "";
        bi.log_message = result.breakpoints[i].log_message ? result.breakpoints[i].log_message : "";
        bi.message = result.breakpoints[i].message ? result.breakpoints[i].message : "";
        breakpoints_.push_back(bi);
    }

    dap_set_breakpoints_result_free(&result);
}

void DebuggerClient::add_source_breakpoint(const std::string& source, int line,
                                           const std::string& condition,
                                           const std::string& hit_condition,
                                           const std::string& log_message)
{
    if (!impl_->client) return;

    // Add to local list, then sync all breakpoints for this source
    BreakpointInfo bi;
    bi.id = -1;
    bi.verified = false;
    bi.source_path = source;
    bi.line = line;
    bi.instruction_reference = 0;
    bi.condition = condition;
    bi.hit_condition = hit_condition;
    bi.log_message = log_message;
    breakpoints_.push_back(bi);

    sync_source_breakpoints(source);
    log(ConsoleEntry::Info, "Breakpoint added at " + source + ":" + std::to_string(line));
}

void DebuggerClient::remove_source_breakpoint(int id)
{
    if (!impl_->client) return;

    // Find the breakpoint and its source
    std::string source;
    for (auto it = breakpoints_.begin(); it != breakpoints_.end(); ++it) {
        if (it->id == id) {
            source = it->source_path;
            breakpoints_.erase(it);
            break;
        }
    }

    if (!source.empty()) {
        sync_source_breakpoints(source);
        log(ConsoleEntry::Info, "Breakpoint " + std::to_string(id) + " removed");
    }
}

void DebuggerClient::clear_breakpoints(const std::string& source)
{
    if (!impl_->client) return;

    breakpoints_.erase(
        std::remove_if(breakpoints_.begin(), breakpoints_.end(),
                        [&source](const BreakpointInfo& b) { return b.source_path == source; }),
        breakpoints_.end());

    sync_source_breakpoints(source);
    log(ConsoleEntry::Info, "Breakpoints cleared for " + source);
}

// ---------------------------------------------------------------------------
// Instruction breakpoints
// ---------------------------------------------------------------------------

void DebuggerClient::set_instruction_breakpoints(const std::vector<InstructionBreakpointInfo>& bps)
{
    if (!impl_->client) return;

    std::vector<DAPInstructionBreakpoint> dap_bps;
    for (const auto& bp : bps) {
        DAPInstructionBreakpoint d = {};
        d.instruction_reference = bp.instruction_reference;
        d.offset = bp.offset;
        d.condition = bp.condition.empty() ? nullptr : const_cast<char*>(bp.condition.c_str());
        d.hit_condition = bp.hit_condition.empty() ? nullptr : const_cast<char*>(bp.hit_condition.c_str());
        dap_bps.push_back(d);
    }

    // Build JSON args manually since dap_client_set_instruction_breakpoints is not implemented
    cJSON* args = cJSON_CreateObject();
    cJSON* bp_array = cJSON_CreateArray();
    for (const auto& bp : bps) {
        cJSON* item = cJSON_CreateObject();
        char addr_str[32];
        snprintf(addr_str, sizeof(addr_str), "0x%X", bp.instruction_reference);
        cJSON_AddStringToObject(item, "instructionReference", addr_str);
        if (bp.offset != 0) cJSON_AddNumberToObject(item, "offset", bp.offset);
        if (!bp.condition.empty()) cJSON_AddStringToObject(item, "condition", bp.condition.c_str());
        if (!bp.hit_condition.empty()) cJSON_AddStringToObject(item, "hitCondition", bp.hit_condition.c_str());
        cJSON_AddItemToArray(bp_array, item);
    }
    cJSON_AddItemToObject(args, "breakpoints", bp_array);

    char* resp_body = nullptr;
    int rc = dap_client_send_request(impl_->client, DAP_CMD_SET_INSTRUCTION_BREAKPOINTS, args, &resp_body);
    cJSON_Delete(args);

    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Error, "Failed to set instruction breakpoints");
        free(resp_body);
        return;
    }

    // Parse response
    instruction_breakpoints_.clear();
    if (resp_body) {
        cJSON* resp = cJSON_Parse(resp_body);
        if (resp) {
            cJSON* bp_arr = cJSON_GetObjectItem(resp, "breakpoints");
            if (bp_arr && cJSON_IsArray(bp_arr)) {
                int arr_size = cJSON_GetArraySize(bp_arr);
                for (int i = 0; i < arr_size; i++) {
                    cJSON* item = cJSON_GetArrayItem(bp_arr, i);
                    InstructionBreakpointInfo ibi;
                    ibi.instruction_reference = (i < (int)bps.size()) ? bps[i].instruction_reference : 0;
                    ibi.offset = (i < (int)bps.size()) ? bps[i].offset : 0;
                    ibi.condition = (i < (int)bps.size()) ? bps[i].condition : "";
                    ibi.hit_condition = (i < (int)bps.size()) ? bps[i].hit_condition : "";
                    cJSON* id_j = cJSON_GetObjectItem(item, "id");
                    ibi.id = id_j ? id_j->valueint : -1;
                    ibi.verified = cJSON_IsTrue(cJSON_GetObjectItem(item, "verified"));
                    cJSON* msg_j = cJSON_GetObjectItem(item, "message");
                    ibi.message = (msg_j && msg_j->valuestring) ? msg_j->valuestring : "";
                    instruction_breakpoints_.push_back(ibi);
                }
            }
            cJSON_Delete(resp);
        }
        free(resp_body);
    }

    log(ConsoleEntry::Info, "Instruction breakpoints set: " + std::to_string(instruction_breakpoints_.size()));
}

// ---------------------------------------------------------------------------
// Data breakpoints (watchpoints)
// ---------------------------------------------------------------------------

void DebuggerClient::add_data_breakpoint(const std::string& data_id, int access_type,
                                         const std::string& condition)
{
    if (!impl_->client) return;

    // Build the full list including the new one
    DataBreakpointInfo new_dbp;
    new_dbp.id = -1;
    new_dbp.verified = false;
    new_dbp.data_id = data_id;
    new_dbp.access_type = access_type;
    new_dbp.address = (uint32_t)strtoul(data_id.c_str(), nullptr, 0);
    new_dbp.condition = condition;
    data_breakpoints_.push_back(new_dbp);

    // Send all data breakpoints to server
    std::vector<DAPDataBreakpoint> dap_dbps;
    for (const auto& dbp : data_breakpoints_) {
        DAPDataBreakpoint d = {};
        d.data_id = const_cast<char*>(dbp.data_id.c_str());
        d.access_type = (DAPDataBreakpointAccessType)dbp.access_type;
        d.condition = dbp.condition.empty() ? nullptr : const_cast<char*>(dbp.condition.c_str());
        dap_dbps.push_back(d);
    }

    DAPSetDataBreakpointsResult result = {};
    int rc = dap_client_set_data_breakpoints(impl_->client, dap_dbps.data(), (int)dap_dbps.size(), &result);
    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Error, "Failed to set data breakpoints");
        data_breakpoints_.pop_back();
        return;
    }

    // Update with server response
    data_breakpoints_.clear();
    for (size_t i = 0; i < result.num_breakpoints; i++) {
        DataBreakpointInfo dbi;
        dbi.id = result.breakpoints[i].id;
        dbi.verified = result.breakpoints[i].verified;
        dbi.data_id = result.breakpoints[i].data_id ? result.breakpoints[i].data_id : "";
        dbi.access_type = (int)result.breakpoints[i].access_type;
        dbi.address = result.breakpoints[i].address;
        dbi.condition = result.breakpoints[i].condition ? result.breakpoints[i].condition : "";
        dbi.message = result.breakpoints[i].message ? result.breakpoints[i].message : "";
        data_breakpoints_.push_back(dbi);
    }

    dap_set_data_breakpoints_result_free(&result);
    log(ConsoleEntry::Info, "Data breakpoint set on " + data_id);
}

void DebuggerClient::remove_data_breakpoint(int id)
{
    if (!impl_->client) return;

    data_breakpoints_.erase(
        std::remove_if(data_breakpoints_.begin(), data_breakpoints_.end(),
                        [id](const DataBreakpointInfo& d) { return d.id == id; }),
        data_breakpoints_.end());

    // Re-send remaining
    std::vector<DAPDataBreakpoint> dap_dbps;
    for (const auto& dbp : data_breakpoints_) {
        DAPDataBreakpoint d = {};
        d.data_id = const_cast<char*>(dbp.data_id.c_str());
        d.access_type = (DAPDataBreakpointAccessType)dbp.access_type;
        d.condition = dbp.condition.empty() ? nullptr : const_cast<char*>(dbp.condition.c_str());
        dap_dbps.push_back(d);
    }

    DAPSetDataBreakpointsResult result = {};
    dap_client_set_data_breakpoints(impl_->client, dap_dbps.empty() ? nullptr : dap_dbps.data(),
                                    (int)dap_dbps.size(), &result);
    dap_set_data_breakpoints_result_free(&result);
    log(ConsoleEntry::Info, "Data breakpoint " + std::to_string(id) + " removed");
}

void DebuggerClient::clear_data_breakpoints()
{
    if (!impl_->client) return;

    data_breakpoints_.clear();
    DAPSetDataBreakpointsResult result = {};
    dap_client_set_data_breakpoints(impl_->client, nullptr, 0, &result);
    dap_set_data_breakpoints_result_free(&result);
    log(ConsoleEntry::Info, "All data breakpoints cleared");
}

// ---------------------------------------------------------------------------
// Disassembly
// ---------------------------------------------------------------------------

void DebuggerClient::disassemble(uint32_t address, int count, bool resolve_symbols)
{
    if (!impl_->client) return;

    DAPDisassembleResult result = {};
    int rc = dap_client_disassemble(impl_->client, address, 0, 0, (size_t)count, resolve_symbols, &result);
    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Error, "Disassemble failed: " + std::string(dap_error_message((DAPError)rc)));
        return;
    }

    disassembly_.clear();
    for (size_t i = 0; i < result.num_instructions; i++) {
        DisassemblyLine dl;
        dl.address = result.instructions[i].address ? result.instructions[i].address : "";
        dl.instruction = result.instructions[i].instruction ? result.instructions[i].instruction : "";
        dl.instruction_bytes = result.instructions[i].instruction_bytes ? result.instructions[i].instruction_bytes : "";
        dl.symbol = result.instructions[i].symbol ? result.instructions[i].symbol : "";
        dl.source_path = result.instructions[i].source_path ? result.instructions[i].source_path : "";
        dl.line = result.instructions[i].line;
        disassembly_.push_back(dl);
    }

    dap_disassemble_result_free(&result);
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

std::string DebuggerClient::read_memory(uint32_t address, uint32_t offset, size_t count)
{
    if (!impl_->client) return "";

    DAPReadMemoryResult result = {};
    int rc = dap_client_read_memory(impl_->client, address, offset, count, &result);
    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Error, "Read memory failed: " + std::string(dap_error_message((DAPError)rc)));
        return "";
    }

    std::string data = result.data ? result.data : "";
    free(result.data);
    free(result.address);
    return data;
}

bool DebuggerClient::write_memory(uint32_t address, uint32_t offset, const std::string& data)
{
    if (!impl_->client) return false;

    DAPWriteMemoryResult result = {};
    int rc = dap_client_write_memory(impl_->client, address, offset, data.c_str(), false, &result);
    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Error, "Write memory failed: " + std::string(dap_error_message((DAPError)rc)));
        return false;
    }

    log(ConsoleEntry::Info, "Wrote " + std::to_string(result.bytes_written) + " bytes at 0x" +
        std::to_string(address));
    return true;
}

// ---------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------

void DebuggerClient::refresh_modules()
{
    if (!impl_->client) return;

    DAPModulesResult result = {};
    int rc = dap_client_modules(impl_->client, 0, 100, &result);
    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Warning, "Failed to get modules");
        return;
    }

    modules_.clear();
    for (size_t i = 0; i < result.num_modules; i++) {
        ModuleInfo mi;
        mi.id = result.modules[i].id ? result.modules[i].id : "";
        mi.name = result.modules[i].name ? result.modules[i].name : "";
        mi.path = result.modules[i].path ? result.modules[i].path : "";
        mi.version = result.modules[i].version ? result.modules[i].version : "";
        mi.symbol_status = result.modules[i].symbol_status ? result.modules[i].symbol_status : "";
        mi.address_range = result.modules[i].address_range ? result.modules[i].address_range : "";
        mi.is_optimized = result.modules[i].is_optimized;
        mi.is_user_code = result.modules[i].is_user_code;
        modules_.push_back(mi);
    }

    // Free module strings
    for (size_t i = 0; i < result.num_modules; i++) {
        free(result.modules[i].id);
        free(result.modules[i].name);
        free(result.modules[i].path);
        free(result.modules[i].version);
        free(result.modules[i].symbol_status);
        free(result.modules[i].symbol_file_path);
        free(result.modules[i].date_time_stamp);
        free(result.modules[i].address_range);
    }
    free(result.modules);
}

// ---------------------------------------------------------------------------
// Evaluate & Set Variable
// ---------------------------------------------------------------------------

void DebuggerClient::evaluate(const std::string& expression, int frame_id)
{
    if (!impl_->client) return;

    log(ConsoleEntry::UserInput, "> " + expression);

    DAPEvaluateResult result = {};
    int rc = dap_client_evaluate(impl_->client, expression.c_str(), frame_id, "repl", &result);
    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Error, "Evaluate failed: " + std::string(dap_error_message((DAPError)rc)));
        return;
    }

    if (result.result) {
        log(ConsoleEntry::DapResponse, result.result);
    }
    dap_evaluate_result_free(&result);
}

void DebuggerClient::set_variable(int variables_reference, const std::string& name, const std::string& value)
{
    if (!impl_->client) return;

    cJSON* args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "variablesReference", variables_reference);
    cJSON_AddStringToObject(args, "name", name.c_str());
    cJSON_AddStringToObject(args, "value", value.c_str());

    char* resp_body = nullptr;
    int rc = dap_client_send_request(impl_->client, DAP_CMD_SET_VARIABLE, args, &resp_body);
    cJSON_Delete(args);
    free(resp_body);

    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Error, "Set variable failed: " + std::string(dap_error_message((DAPError)rc)));
        return;
    }
    log(ConsoleEntry::Info, "Set " + name + " = " + value);

    // Refresh variables to show new value
    if (!stack_frames_.empty()) {
        refresh_scopes(stack_frames_[0].id);
    }
}

// ---------------------------------------------------------------------------
// Terminal console I/O
// ---------------------------------------------------------------------------

void DebuggerClient::console_enable(int terminal, bool enable)
{
    if (!impl_->client) return;

    int rc = dap_client_console_enable(impl_->client, terminal, enable);
    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Error, "Console enable failed: " + std::string(dap_error_message((DAPError)rc)));
        return;
    }

    if (enable) {
        active_terminal_ = terminal;
        log(ConsoleEntry::Info, "Console capture enabled on terminal " + std::to_string(terminal));
    } else {
        active_terminal_ = -1;
        log(ConsoleEntry::Info, "Console capture disabled on terminal " + std::to_string(terminal));
    }
}

void DebuggerClient::console_write(int terminal, const std::string& input)
{
    if (!impl_->client) return;

    int rc = dap_client_console_write(impl_->client, terminal, input.c_str(), false);
    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Error, "Console write failed: " + std::string(dap_error_message((DAPError)rc)));
    }
}

// ---------------------------------------------------------------------------
// Symbol list (custom DAP extension)
// ---------------------------------------------------------------------------

void DebuggerClient::fetch_symbols(const std::string& filter, int symbol_type)
{
    if (!impl_->client) return;

    cJSON* args = cJSON_CreateObject();
    if (!filter.empty()) cJSON_AddStringToObject(args, "filter", filter.c_str());
    if (symbol_type > 0) cJSON_AddNumberToObject(args, "symbolType", symbol_type);

    log_protocol_sent("symbolList", args);

    char* resp_body = nullptr;
    int rc = dap_client_send_request(impl_->client, DAP_CMD_SYMBOL_LIST, args, &resp_body);
    cJSON_Delete(args);

    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Warning, "symbolList not supported or failed");
        free(resp_body);
        return;
    }

    symbols_.clear();
    if (resp_body) {
        cJSON* resp = cJSON_Parse(resp_body);
        if (resp) {
            cJSON* syms = cJSON_GetObjectItem(resp, "symbols");
            if (syms && cJSON_IsArray(syms)) {
                int n = cJSON_GetArraySize(syms);
                for (int i = 0; i < n; i++) {
                    cJSON* item = cJSON_GetArrayItem(syms, i);
                    SymbolInfo si;
                    cJSON* v;
                    v = cJSON_GetObjectItem(item, "name");
                    si.name = (v && v->valuestring) ? v->valuestring : "";
                    v = cJSON_GetObjectItem(item, "address");
                    si.address = v ? (uint32_t)v->valueint : 0;
                    v = cJSON_GetObjectItem(item, "type");
                    si.type = (v && v->valuestring) ? v->valuestring : "";
                    v = cJSON_GetObjectItem(item, "sourcePath");
                    si.source_path = (v && v->valuestring) ? v->valuestring : "";
                    v = cJSON_GetObjectItem(item, "line");
                    si.line = v ? v->valueint : 0;
                    symbols_.push_back(si);
                }
            }
            cJSON_Delete(resp);
        }
        free(resp_body);
    }

    log(ConsoleEntry::Info, "Symbols: " + std::to_string(symbols_.size()) + " found");
}

// ---------------------------------------------------------------------------
// Polling & event handling
// ---------------------------------------------------------------------------

void DebuggerClient::poll()
{
    if (!impl_->client || state_ == ClientState::Disconnected) return;

    // Drain all available messages with a short timeout so the UI stays responsive
    int saved_timeout = impl_->client->timeout_ms;
    impl_->client->timeout_ms = 10;

    for (;;) {
        cJSON* message = nullptr;
        int rc = dap_client_receive_message(impl_->client, &message);

        if (rc != 0 || !message) {
            // Check for transport error (server died)
            if (rc == DAP_ERROR_TRANSPORT && impl_->client && !impl_->client->connected) {
                log(ConsoleEntry::Error, "Connection lost (server died)");
                impl_->client->timeout_ms = saved_timeout;
                force_close();
                return;
            }
            break;  // No more messages available
        }

        log_protocol_received(message);

        const char* type_str = cJSON_GetStringValue(cJSON_GetObjectItem(message, "type"));
        if (!type_str) {
            cJSON_Delete(message);
            continue;
        }

        if (strcmp(type_str, "event") == 0) {
            const char* event = cJSON_GetStringValue(cJSON_GetObjectItem(message, "event"));
            cJSON* body = cJSON_GetObjectItem(message, "body");
            if (event) {
                handle_event(event, body);
            }
        } else if (strcmp(type_str, "response") == 0) {
            const char* cmd = cJSON_GetStringValue(cJSON_GetObjectItem(message, "command"));
            bool success = cJSON_IsTrue(cJSON_GetObjectItem(message, "success"));

            // Always log responses
            if (cmd) {
                cJSON* msg_j = cJSON_GetObjectItem(message, "message");
                std::string detail;
                if (!success && msg_j && msg_j->valuestring) {
                    detail = std::string(" - ") + msg_j->valuestring;
                }
                log(ConsoleEntry::DapResponse,
                    std::string("Response: ") + cmd + (success ? " [ok]" : " [FAIL]") + detail);
            }

            // Capture server capabilities from initialize response
            if (cmd && strcmp(cmd, "initialize") == 0 && success) {
                cJSON* body = cJSON_GetObjectItem(message, "body");
                if (body) {
                    parse_capabilities(body, server_capabilities_);
                    log(ConsoleEntry::Info, "Server capabilities: " +
                        std::to_string(server_capabilities_.size()) + " entries");
                }
            }

            // Handle launch failure
            if (cmd && strcmp(cmd, "launch") == 0 && !success) {
                state_ = ClientState::Initialized;
                log(ConsoleEntry::Error, "Launch failed");
            }

            // Handle disconnect response
            if (cmd && strcmp(cmd, "disconnect") == 0) {
                state_ = ClientState::Disconnected;
            }
        }

        cJSON_Delete(message);
    }

    impl_->client->timeout_ms = saved_timeout;

    // Now that all pending messages are drained, do deferred data queries.
    // This avoids the problem where blocking queries inside on_stopped()
    // would consume pending async responses (launch, configurationDone, etc.)
    if (needs_refresh_ && state_ == ClientState::Stopped) {
        needs_refresh_ = false;

        refresh_threads();
        refresh_stack_trace();

        if (auto_disassemble_ && !stack_frames_.empty()) {
            uint32_t ip = (uint32_t)stack_frames_[0].instruction_pointer;
            if (ip > 0) {
                disassemble(ip, disassemble_count_);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Event dispatch
// ---------------------------------------------------------------------------

void DebuggerClient::handle_event(const char* event_name, void* body_json)
{
    cJSON* body = (cJSON*)body_json;

    log(ConsoleEntry::DapEvent, std::string("Event: ") + event_name);

    if (strcmp(event_name, "stopped") == 0) {
        handle_stopped_event(body);
    } else if (strcmp(event_name, "continued") == 0) {
        handle_continued_event(body);
    } else if (strcmp(event_name, "terminated") == 0) {
        state_ = ClientState::Terminated;
        stack_frames_.clear();
        scopes_.clear();
        variables_.clear();
        disassembly_.clear();
        stop_reason_.clear();
        hit_breakpoint_ids_.clear();
        log(ConsoleEntry::Info, "Program terminated");
    } else if (strcmp(event_name, "exited") == 0) {
        cJSON* exit_code = body ? cJSON_GetObjectItem(body, "exitCode") : nullptr;
        int code = exit_code ? exit_code->valueint : -1;
        log(ConsoleEntry::Info, "Program exited with code " + std::to_string(code));
        state_ = ClientState::Terminated;
    } else if (strcmp(event_name, "output") == 0) {
        handle_output_event(body);
    } else if (strcmp(event_name, "initialized") == 0) {
        log(ConsoleEntry::Info, "Debug adapter initialized, ready for configuration");
    } else if (strcmp(event_name, "thread") == 0) {
        handle_thread_event(body);
    } else if (strcmp(event_name, "breakpoint") == 0) {
        handle_breakpoint_event(body);
    } else if (strcmp(event_name, "process") == 0) {
        handle_process_event(body);
    } else if (strcmp(event_name, "module") == 0) {
        handle_module_event(body);
    } else if (strcmp(event_name, "memory") == 0) {
        handle_memory_event(body);
    } else if (strcmp(event_name, "capabilities") == 0) {
        handle_capabilities_event(body);
    } else if (strcmp(event_name, "progressStart") == 0) {
        cJSON* title = body ? cJSON_GetObjectItem(body, "title") : nullptr;
        if (title && title->valuestring)
            log(ConsoleEntry::Info, std::string("Progress: ") + title->valuestring);
    } else if (strcmp(event_name, "progressUpdate") == 0) {
        cJSON* msg = body ? cJSON_GetObjectItem(body, "message") : nullptr;
        if (msg && msg->valuestring)
            log(ConsoleEntry::Info, std::string("Progress: ") + msg->valuestring);
    } else if (strcmp(event_name, "progressEnd") == 0) {
        cJSON* msg = body ? cJSON_GetObjectItem(body, "message") : nullptr;
        log(ConsoleEntry::Info, msg && msg->valuestring
            ? std::string("Progress done: ") + msg->valuestring : "Progress done");
    } else if (strcmp(event_name, "invalidated") == 0) {
        // Server says cached data is stale; refresh everything on next stop
        log(ConsoleEntry::Info, "Server invalidated cached data");
    } else {
        log(ConsoleEntry::Warning, std::string("Unhandled event: ") + event_name);
    }
}

// ---------------------------------------------------------------------------
// stopped -- the most important event: query threads, stack, variables, disasm
// ---------------------------------------------------------------------------

void DebuggerClient::handle_stopped_event(void* body_json)
{
    cJSON* body = (cJSON*)body_json;
    state_ = ClientState::Stopped;

    stop_reason_ = "unknown";
    hit_breakpoint_ids_.clear();

    if (body) {
        cJSON* r = cJSON_GetObjectItem(body, "reason");
        if (r && r->valuestring) stop_reason_ = r->valuestring;

        cJSON* tid = cJSON_GetObjectItem(body, "threadId");
        if (tid) thread_id_ = tid->valueint;

        cJSON* desc = cJSON_GetObjectItem(body, "description");
        if (desc && desc->valuestring) {
            log(ConsoleEntry::Info, std::string("Stopped: ") + stop_reason_ + " - " + desc->valuestring);
        } else {
            log(ConsoleEntry::Info, std::string("Stopped: ") + stop_reason_);
        }

        // Collect hit breakpoint IDs
        cJSON* bp_ids = cJSON_GetObjectItem(body, "hitBreakpointIds");
        if (bp_ids && cJSON_IsArray(bp_ids)) {
            int n = cJSON_GetArraySize(bp_ids);
            for (int i = 0; i < n; i++) {
                cJSON* id = cJSON_GetArrayItem(bp_ids, i);
                if (id) hit_breakpoint_ids_.push_back(id->valueint);
            }
            if (!hit_breakpoint_ids_.empty()) {
                std::string ids_str;
                for (int id : hit_breakpoint_ids_) {
                    if (!ids_str.empty()) ids_str += ", ";
                    ids_str += std::to_string(id);
                }
                log(ConsoleEntry::Info, "Hit breakpoint(s): " + ids_str);
            }
        }
    } else {
        log(ConsoleEntry::Info, "Stopped (no details)");
    }

    on_stopped();
}

// ---------------------------------------------------------------------------
// continued -- execution resumed
// ---------------------------------------------------------------------------

void DebuggerClient::handle_continued_event(void* body_json)
{
    cJSON* body = (cJSON*)body_json;
    state_ = ClientState::Running;
    stop_reason_.clear();
    hit_breakpoint_ids_.clear();

    if (body) {
        cJSON* tid = cJSON_GetObjectItem(body, "threadId");
        if (tid) {
            log(ConsoleEntry::Info, "Thread " + std::to_string(tid->valueint) + " continued");
        }
        cJSON* all = cJSON_GetObjectItem(body, "allThreadsContinued");
        if (all && cJSON_IsTrue(all)) {
            log(ConsoleEntry::Info, "All threads continued");
        }
    } else {
        log(ConsoleEntry::Info, "Execution continued");
    }

    // Clear stale stopped-state data
    stack_frames_.clear();
    scopes_.clear();
    variables_.clear();
}

// ---------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------

void DebuggerClient::handle_output_event(void* body_json)
{
    cJSON* body = (cJSON*)body_json;
    if (!body) return;

    cJSON* output = cJSON_GetObjectItem(body, "output");
    if (!output || !output->valuestring) return;

    cJSON* cat = cJSON_GetObjectItem(body, "category");
    const char* category = cat && cat->valuestring ? cat->valuestring : "console";

    // Route stdout to terminal output buffer when console capture is active
    if (active_terminal_ >= 0 && strcmp(category, "stdout") == 0) {
        terminal_output_.push_back(output->valuestring);
        return;
    }

    ConsoleEntry::Category entry_cat = ConsoleEntry::Info;
    if (strcmp(category, "stderr") == 0)
        entry_cat = ConsoleEntry::Error;
    else if (strcmp(category, "important") == 0)
        entry_cat = ConsoleEntry::Warning;

    std::string text = output->valuestring;
    while (!text.empty() && text.back() == '\n') text.pop_back();
    if (!text.empty()) {
        log(entry_cat, text);
    }
}

// ---------------------------------------------------------------------------
// thread -- track thread creation/exit
// ---------------------------------------------------------------------------

void DebuggerClient::handle_thread_event(void* body_json)
{
    cJSON* body = (cJSON*)body_json;
    if (!body) return;

    cJSON* reason = cJSON_GetObjectItem(body, "reason");
    cJSON* tid = cJSON_GetObjectItem(body, "threadId");
    if (!reason || !reason->valuestring || !tid) return;

    int id = tid->valueint;

    if (strcmp(reason->valuestring, "started") == 0) {
        // Add thread if not already tracked
        bool found = false;
        for (const auto& t : threads_) {
            if (t.id == id) { found = true; break; }
        }
        if (!found) {
            ThreadInfo ti;
            ti.id = id;
            ti.name = "Thread " + std::to_string(id);
            threads_.push_back(ti);
        }
        log(ConsoleEntry::Info, "Thread " + std::to_string(id) + " started");
    } else if (strcmp(reason->valuestring, "exited") == 0) {
        threads_.erase(
            std::remove_if(threads_.begin(), threads_.end(),
                           [id](const ThreadInfo& t) { return t.id == id; }),
            threads_.end());
        log(ConsoleEntry::Info, "Thread " + std::to_string(id) + " exited");
    }
}

// ---------------------------------------------------------------------------
// breakpoint -- server-initiated breakpoint state change
// ---------------------------------------------------------------------------

void DebuggerClient::handle_breakpoint_event(void* body_json)
{
    cJSON* body = (cJSON*)body_json;
    if (!body) return;

    cJSON* reason = cJSON_GetObjectItem(body, "reason");
    cJSON* bp = cJSON_GetObjectItem(body, "breakpoint");
    if (!reason || !reason->valuestring || !bp) return;

    cJSON* bp_id_j = cJSON_GetObjectItem(bp, "id");
    int bp_id = bp_id_j ? bp_id_j->valueint : -1;
    bool verified = cJSON_IsTrue(cJSON_GetObjectItem(bp, "verified"));
    cJSON* msg_j = cJSON_GetObjectItem(bp, "message");
    std::string msg = (msg_j && msg_j->valuestring) ? msg_j->valuestring : "";

    if (strcmp(reason->valuestring, "changed") == 0 || strcmp(reason->valuestring, "new") == 0) {
        // Update existing or add new
        bool found = false;
        for (auto& b : breakpoints_) {
            if (b.id == bp_id) {
                b.verified = verified;
                if (!msg.empty()) b.message = msg;
                found = true;
                break;
            }
        }
        if (!found) {
            BreakpointInfo bi;
            bi.id = bp_id;
            bi.verified = verified;
            bi.message = msg;
            cJSON* line_j = cJSON_GetObjectItem(bp, "line");
            bi.line = line_j ? line_j->valueint : 0;
            cJSON* src = cJSON_GetObjectItem(bp, "source");
            if (src) {
                cJSON* path = cJSON_GetObjectItem(src, "path");
                if (path && path->valuestring) bi.source_path = path->valuestring;
            }
            breakpoints_.push_back(bi);
        }
        log(ConsoleEntry::Info, "Breakpoint " + std::to_string(bp_id) + " " + reason->valuestring +
            (verified ? " (verified)" : " (unverified)"));
    } else if (strcmp(reason->valuestring, "removed") == 0) {
        breakpoints_.erase(
            std::remove_if(breakpoints_.begin(), breakpoints_.end(),
                           [bp_id](const BreakpointInfo& b) { return b.id == bp_id; }),
            breakpoints_.end());
        log(ConsoleEntry::Info, "Breakpoint " + std::to_string(bp_id) + " removed by server");
    }
}

// ---------------------------------------------------------------------------
// process -- store process info
// ---------------------------------------------------------------------------

void DebuggerClient::handle_process_event(void* body_json)
{
    cJSON* body = (cJSON*)body_json;
    if (!body) return;

    cJSON* name = cJSON_GetObjectItem(body, "name");
    if (name && name->valuestring) process_name_ = name->valuestring;

    cJSON* pid = cJSON_GetObjectItem(body, "systemProcessId");
    if (pid) process_id_ = pid->valueint;

    cJSON* method = cJSON_GetObjectItem(body, "startMethod");
    std::string start = (method && method->valuestring) ? method->valuestring : "unknown";

    log(ConsoleEntry::Info, "Process: " + process_name_ + " (pid " + std::to_string(process_id_) +
        ", " + start + ")");
}

// ---------------------------------------------------------------------------
// module -- track loaded/unloaded modules
// ---------------------------------------------------------------------------

void DebuggerClient::handle_module_event(void* body_json)
{
    cJSON* body = (cJSON*)body_json;
    if (!body) return;

    cJSON* reason = cJSON_GetObjectItem(body, "reason");
    cJSON* mod = cJSON_GetObjectItem(body, "module");
    if (!reason || !reason->valuestring || !mod) return;

    cJSON* id_j = cJSON_GetObjectItem(mod, "id");
    std::string mod_id = (id_j && id_j->valuestring) ? id_j->valuestring : "";
    cJSON* name_j = cJSON_GetObjectItem(mod, "name");
    std::string mod_name = (name_j && name_j->valuestring) ? name_j->valuestring : "";

    if (strcmp(reason->valuestring, "new") == 0) {
        ModuleInfo mi;
        mi.id = mod_id;
        mi.name = mod_name;
        cJSON* path_j = cJSON_GetObjectItem(mod, "path");
        mi.path = (path_j && path_j->valuestring) ? path_j->valuestring : "";
        cJSON* sym_j = cJSON_GetObjectItem(mod, "symbolStatus");
        mi.symbol_status = (sym_j && sym_j->valuestring) ? sym_j->valuestring : "";
        modules_.push_back(mi);
        log(ConsoleEntry::Info, "Module loaded: " + mod_name);
    } else if (strcmp(reason->valuestring, "removed") == 0) {
        modules_.erase(
            std::remove_if(modules_.begin(), modules_.end(),
                           [&mod_id](const ModuleInfo& m) { return m.id == mod_id; }),
            modules_.end());
        log(ConsoleEntry::Info, "Module removed: " + mod_name);
    }
}

// ---------------------------------------------------------------------------
// memory -- log memory change, user can re-read
// ---------------------------------------------------------------------------

void DebuggerClient::handle_memory_event(void* body_json)
{
    cJSON* body = (cJSON*)body_json;
    if (!body) return;

    cJSON* ref = cJSON_GetObjectItem(body, "memoryReference");
    cJSON* offset = cJSON_GetObjectItem(body, "offset");
    cJSON* count = cJSON_GetObjectItem(body, "count");

    std::string addr = (ref && ref->valuestring) ? ref->valuestring : "?";
    int off = offset ? offset->valueint : 0;
    int cnt = count ? count->valueint : 0;

    log(ConsoleEntry::Info, "Memory changed at " + addr + " offset " + std::to_string(off) +
        " (" + std::to_string(cnt) + " bytes)");
}

// ---------------------------------------------------------------------------
// capabilities -- server announcing updated capabilities
// ---------------------------------------------------------------------------

void DebuggerClient::handle_capabilities_event(void* body_json)
{
    cJSON* body = (cJSON*)body_json;
    if (body) {
        cJSON* caps = cJSON_GetObjectItem(body, "capabilities");
        if (caps) {
            parse_capabilities(caps, server_capabilities_);
        } else {
            // Body itself might be the capabilities object
            parse_capabilities(body, server_capabilities_);
        }
    }
    log(ConsoleEntry::Info, "Server capabilities updated (" +
        std::to_string(server_capabilities_.size()) + " entries)");
}

// ---------------------------------------------------------------------------
// Thread refresh
// ---------------------------------------------------------------------------

void DebuggerClient::refresh_threads()
{
    if (!impl_->client) return;

    DAPThread* dap_threads = nullptr;
    int count = 0;
    int rc = dap_client_get_threads(impl_->client, &dap_threads, &count);
    if (rc != DAP_ERROR_NONE) {
        log(ConsoleEntry::Warning, "Failed to get threads");
        return;
    }

    threads_.clear();
    for (int i = 0; i < count; i++) {
        ThreadInfo ti;
        ti.id = dap_threads[i].id;
        ti.name = dap_threads[i].name ? dap_threads[i].name : "";
        threads_.push_back(ti);
    }
    free(dap_threads);
}

// ---------------------------------------------------------------------------
// on_stopped -- automatic queries after any stop
// ---------------------------------------------------------------------------

void DebuggerClient::on_stopped()
{
    // Don't do blocking queries here -- there may be pending async responses
    // (launch, configurationDone, continue, etc.) in the transport buffer that
    // would interfere. Set a flag and let poll() drain everything first.
    needs_refresh_ = true;
}

const char* DebuggerClient::state_string() const
{
    switch (state_) {
    case ClientState::Disconnected: return "Disconnected";
    case ClientState::Connected:    return "Connected";
    case ClientState::Initialized:  return "Initialized";
    case ClientState::Running:      return "Running";
    case ClientState::Stopped:      return "Stopped";
    case ClientState::Terminated:   return "Terminated";
    }
    return "Unknown";
}
