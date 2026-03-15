
-- =============================================================================
-- PS5 Syscall Enumerator for Luac0re (FW 12.07)
-- Requires: syscall.init(), jit_init(), init_native_functions() already called
-- Usage: place at /savedata0/lua/auto.lua or send via remote_lua_loader
-- =============================================================================

-- ============================================================================
-- Configuration
-- ============================================================================

local config = {
    PC_IP          = "192.168.1.100",  -- IP of UDP log receiver on your PC
    LOG_PORT       = 9000,             -- UDP port for remote logging
    SYSCALL_MIN    = 0,                -- First syscall ID to probe
    SYSCALL_MAX    = 1024,             -- Last syscall ID to probe
    TIMEOUT_MS     = 100,              -- Delay between probes in milliseconds
    LOG_BATCH_SIZE = 10,               -- Flush remote log every N entries
    ENABLE_REMOTE_LOG = true,          -- Send results over UDP
    ENABLE_LOCAL_LOG  = true,          -- Write results to local file
    LOG_FILE = "/savedata0/syscall_enum.log",
    CONSOLE_MIN_INTEREST = 6,          -- Minimum interest score to print to console
}

-- ============================================================================
-- Errno constants (FreeBSD/PS5 kernel)
-- ============================================================================

local ERRNO = {
    EPERM  = 1,   -- Operation not permitted
    EAGAIN = 11,  -- Resource temporarily unavailable
    ENOMEM = 12,  -- Cannot allocate memory
    EACCES = 13,  -- Permission denied
    EFAULT = 14,  -- Bad address
    EINVAL = 22,  -- Invalid argument
    ENOSYS = 78,  -- Function not implemented
}

-- ============================================================================
-- Classification matrix (errno → interest score + action)
-- ============================================================================

local CLASSIFICATION = {
    [ERRNO.ENOSYS] = { class = "NOT_IMPLEMENTED",  interest = 0,  action = "SKIP"        },
    [ERRNO.EPERM]  = { class = "BLOCKED_SANDBOX",  interest = 9,  action = "INVESTIGATE" },
    [ERRNO.EACCES] = { class = "BLOCKED_SANDBOX",  interest = 8,  action = "INVESTIGATE" },
    [ERRNO.EFAULT] = { class = "ACTIVE_VULNERABLE", interest = 10, action = "FUZZ"       },
    [ERRNO.EINVAL] = { class = "ACTIVE_VALID",      interest = 7,  action = "FUZZ"       },
    [ERRNO.EAGAIN] = { class = "ACTIVE_BLOCKED",    interest = 5,  action = "RETRY"      },
    [ERRNO.ENOMEM] = { class = "ACTIVE_LIMITED",    interest = 6,  action = "OPTIMIZE"   },
}

-- ============================================================================
-- Network helpers
-- ============================================================================

local function htons(port)
    return ((port << 8) | (port >> 8)) & 0xFFFF
end

-- Parse "A.B.C.D" and write the four octets in network order into sockaddr+4
local function write_ip(sockaddr, ip_str)
    local a, b, c, d = ip_str:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    write8(sockaddr + 4, tonumber(a))
    write8(sockaddr + 5, tonumber(b))
    write8(sockaddr + 6, tonumber(c))
    write8(sockaddr + 7, tonumber(d))
end

-- ============================================================================
-- Logger
-- ============================================================================

local Logger = {}
Logger.__index = Logger

function Logger:new()
    local obj = setmetatable({}, Logger)
    obj.buffer     = {}
    obj.log_count  = 0
    obj.start_time = os.time()
    obj.udp_fd     = -1
    obj.sockaddr   = nil
    obj.send_buf   = malloc(4096)  -- Reusable UDP send buffer

    if config.ENABLE_LOCAL_LOG then
        local f = io.open(config.LOG_FILE, "w")
        if f then
            f:write(string.format(
                "-- Luac0re PS5 Syscall Enumerator | FW: %s | %s\n",
                FW_VERSION or "unknown", os.date()))
            f:close()
        end
    end

    if config.ENABLE_REMOTE_LOG then
        obj:init_udp()
    end

    return obj
end

function Logger:init_udp()
    local fd = syscall.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    if fd < 0 then
        send_notification("syscall_enumerator: UDP socket() failed")
        return
    end
    self.udp_fd = fd

    self.sockaddr = malloc(16)
    for i = 0, 15 do write8(self.sockaddr + i, 0) end
    write8(self.sockaddr + 1, AF_INET)
    write16(self.sockaddr + 2, htons(config.LOG_PORT))
    write_ip(self.sockaddr, config.PC_IP)
end

-- Retrieve current errno via libc_error() / libc_strerror()
function Logger:get_errno()
    local error_addr = libc_error()
    return read64(error_addr) & 0xFFFFFFFF
end

function Logger:get_strerror(errno_val)
    local str_addr = libc_strerror(errno_val)
    if str_addr and str_addr ~= 0 then
        return read_null_terminated_string(str_addr)
    end
    return "unknown"
end

function Logger:log(id, success, errno_val)
    local info      = CLASSIFICATION[errno_val]
                   or { class = "UNKNOWN", interest = 3, action = "LOG" }
    local strerror  = self:get_strerror(errno_val)

    local entry = {
        timestamp = os.time(),
        id        = id,
        success   = success,
        errno     = errno_val,
        strerror  = strerror,
        class     = info.class,
        interest  = info.interest,
        action    = info.action,
    }

    self.log_count = self.log_count + 1
    table.insert(self.buffer, entry)

    if config.ENABLE_LOCAL_LOG then
        self:write_local(entry)
    end

    -- Print only entries with meaningful interest score
    if entry.interest >= config.CONSOLE_MIN_INTEREST then
        printf("[%04d] Success:%-5s Errno:%3d (%-15s) | %-20s | Interest:%2d | %s",
            id, tostring(success), errno_val, strerror,
            info.class, info.interest, info.action)
    end

    if #self.buffer >= config.LOG_BATCH_SIZE then
        self:flush_remote()
    end
end

function Logger:write_local(entry)
    local f = io.open(config.LOG_FILE, "a")
    if f then
        f:write(string.format(
            "[%d] ID:%04d | Success:%-5s | Errno:%3d | Class:%-20s | Interest:%2d | Action:%-12s | %s\n",
            entry.timestamp, entry.id, tostring(entry.success),
            entry.errno, entry.class, entry.interest, entry.action,
            entry.strerror))
        f:close()
    end
end

function Logger:to_json(entries)
    local parts = {}
    for i, e in ipairs(entries) do
        local comma = (i < #entries) and "," or ""
        parts[#parts + 1] = string.format(
            '{"id":%d,"errno":%d,"class":"%s","interest":%d,"action":"%s","success":%s}%s',
            e.id, e.errno, e.class, e.interest, e.action,
            e.success and "true" or "false", comma)
    end
    return '{"entries":[' .. table.concat(parts) .. ']}'
end

function Logger:flush_remote()
    if not config.ENABLE_REMOTE_LOG or #self.buffer == 0 then
        self.buffer = {}
        return
    end
    if self.udp_fd < 0 then
        self.buffer = {}
        return
    end

    local json = self:to_json(self.buffer)
    -- Guard against oversized JSON (each entry is ~80 chars; batches of 10 are ~800 bytes)
    if #json > 4095 then
        self.buffer = {}
        return
    end
    write_string(self.send_buf, json)

    pcall(function()
        syscall.sendto(self.udp_fd, self.send_buf, #json, 0, self.sockaddr, 16)
    end)

    self.buffer = {}
end

function Logger:close()
    self:flush_remote()
    if self.udp_fd >= 0 then
        syscall.close(self.udp_fd)
        self.udp_fd = -1
    end
end

function Logger:print_summary(stats)
    local elapsed = os.time() - self.start_time
    print(string.rep("=", 70))
    print("  SYSCALL ENUMERATOR - SCAN COMPLETE")
    print(string.rep("=", 70))
    printf("  Syscall range       : %d - %d", config.SYSCALL_MIN, config.SYSCALL_MAX)
    printf("  Total scanned       : %d", stats.total)
    printf("  Implemented         : %d", stats.implemented)
    printf("    Sandbox blocked   : %d  (EPERM/EACCES - escape candidates)",
        stats.blocked_sandbox)
    printf("    Active vulnerable : %d  (EFAULT - prime fuzz targets)",
        stats.active_vulnerable)
    printf("    Active valid      : %d  (EINVAL - active, wrong params)",
        stats.active_valid)
    printf("    Active limited    : %d  (ENOMEM)", stats.active_limited)
    printf("    Rate limited      : %d  (EAGAIN)", stats.active_blocked)
    printf("  Not implemented     : %d  (ENOSYS)", stats.not_implemented)
    printf("  Unknown / other     : %d", stats.other)
    printf("  Elapsed             : %d seconds", elapsed)
    if config.ENABLE_LOCAL_LOG then
        printf("  Log file            : %s", config.LOG_FILE)
    end
    print(string.rep("=", 70))
end

-- ============================================================================
-- SyscallEnumerator
-- ============================================================================

local SyscallEnumerator = {}
SyscallEnumerator.__index = SyscallEnumerator

function SyscallEnumerator:new(logger, use_jit)
    local obj  = setmetatable({}, SyscallEnumerator)
    obj.logger  = logger
    obj.use_jit = use_jit or false
    obj.stats   = {
        total              = 0,
        implemented        = 0,
        blocked_sandbox    = 0,
        active_vulnerable  = 0,
        active_valid       = 0,
        active_limited     = 0,
        active_blocked     = 0,
        not_implemented    = 0,
        other              = 0,
    }
    return obj
end

-- Build a one-shot callable for syscall id using the appropriate context
function SyscallEnumerator:make_fn(id)
    if self.use_jit then
        return jit_func_wrap_with_rax(jit_syscall.syscall_address, id)
    else
        return func_wrap_with_rax(syscall.syscall_address, id)
    end
end

-- Probe a single syscall ID and return (success, errno_val)
function SyscallEnumerator:probe(id)
    local call_fn = self:make_fn(id)

    -- pcall protects against Lua-level errors from the ROP wrapper.
    -- Remote UDP logging ensures data is safe even on kernel panic.
    local success = pcall(function()
        call_fn(0, 0, 0, 0, 0, 0)
    end)

    local errno_val = self.logger:get_errno()
    return success, errno_val
end

function SyscallEnumerator:update_stats(errno_val)
    self.stats.total = self.stats.total + 1

    if errno_val == ERRNO.ENOSYS then
        self.stats.not_implemented = self.stats.not_implemented + 1
        return
    end

    self.stats.implemented = self.stats.implemented + 1

    if errno_val == ERRNO.EPERM or errno_val == ERRNO.EACCES then
        self.stats.blocked_sandbox = self.stats.blocked_sandbox + 1
    elseif errno_val == ERRNO.EFAULT then
        self.stats.active_vulnerable = self.stats.active_vulnerable + 1
    elseif errno_val == ERRNO.EINVAL then
        self.stats.active_valid = self.stats.active_valid + 1
    elseif errno_val == ERRNO.ENOMEM then
        self.stats.active_limited = self.stats.active_limited + 1
    elseif errno_val == ERRNO.EAGAIN then
        self.stats.active_blocked = self.stats.active_blocked + 1
    else
        self.stats.other = self.stats.other + 1
    end
end

function SyscallEnumerator:enumerate()
    local ctx = self.use_jit and "JIT" or "main"
    print(string.rep("=", 70))
    printf("  PS5 Syscall Enumerator | Luac0re | FW: %s | ctx: %s",
        FW_VERSION or "unknown", ctx)
    printf("  Scanning IDs %d-%d | delay: %dms | batch: %d",
        config.SYSCALL_MIN, config.SYSCALL_MAX,
        config.TIMEOUT_MS, config.LOG_BATCH_SIZE)
    if config.ENABLE_REMOTE_LOG then
        printf("  Remote log -> %s:%d", config.PC_IP, config.LOG_PORT)
    end
    if config.ENABLE_LOCAL_LOG then
        printf("  Local log  -> %s", config.LOG_FILE)
    end
    print(string.rep("=", 70))

    local total = config.SYSCALL_MAX - config.SYSCALL_MIN + 1

    for id = config.SYSCALL_MIN, config.SYSCALL_MAX do
        local success, errno_val = self:probe(id)
        self:update_stats(errno_val)
        self.logger:log(id, success, errno_val)

        if config.TIMEOUT_MS > 0 then
            sceKernelUsleep(config.TIMEOUT_MS * 1000)
        end

        -- Progress indicator every 64 syscalls
        if (id - config.SYSCALL_MIN) % 64 == 0 then
            local done = id - config.SYSCALL_MIN + 1
            io.write(string.format("\r  [%d/%d] %.1f%%  ",
                done, total, done / total * 100))
            io.flush()
        end
    end

    io.write("\n")
    self.logger:close()
    self.logger:print_summary(self.stats)
end

-- ============================================================================
-- main()
-- ============================================================================

function main()
    -- use_jit=false → regular syscall context (change to true for JIT context)
    local logger     = Logger:new()
    local enumerator = SyscallEnumerator:new(logger, false)
    enumerator:enumerate()
end

main()
