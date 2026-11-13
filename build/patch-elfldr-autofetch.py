#!/usr/bin/env python3
"""Patch upstream elfldr to fetch NexHEN and report the actual launch result."""
from pathlib import Path

# Bootstrap-side TCP client and visible status reporting.
p = Path("bootstrap-elf.c")
s = p.read_text()
needle = '#include <signal.h>\n'
addition = '''#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
'''
if "static int\nsend_nexhen_uri" not in s:
    if needle not in s:
        raise SystemExit("bootstrap-elf.c include anchor missing")
    s = s.replace(needle, needle + addition, 1)
    anchor = 'int\nmain(void) {'
    helper = r"""
/* Send a newline-terminated HTTPS URI to elfldr's raw TCP socket, then wait
 * for an explicit fetch/spawn result. */
static int
send_nexhen_uri(void) {
  static const char uri[] =
      "https://raw.githubusercontent.com/CrispyKilledIt/afterglow/50ee030c6738e43301f852abbaf74f332b64c3d7/"
      "nexHEN-ps4.elf\n";
  struct sockaddr_in addr = {0};
  struct timeval timeout = {180, 0};
  int fd = -1;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(9021);
  if(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
    return -1;
  }

  /* Wait for the child server to bind before sending the request. */
  for(int i = 0; i < 60; i++) {
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd >= 0 && connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      break;
    }
    if(fd >= 0) {
      close(fd);
      fd = -1;
    }
    usleep(250000);
  }
  if(fd < 0) {
    LOG_PUTS("Could not connect to local ELF loader on port 9021");
    notify("Afterglow: ELF loader did not open port 9021");
    return -1;
  }

  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &(int){1}, sizeof(int));

  size_t off = 0;
  while(off < sizeof(uri) - 1) {
    ssize_t n = send(fd, uri + off, sizeof(uri) - 1 - off, 0);
    if(n <= 0) {
      close(fd);
      LOG_PUTS("Failed sending NexHEN URI to ELF loader");
      notify("Afterglow: failed to send NexHEN request");
      return -1;
    }
    off += (size_t)n;
  }

  shutdown(fd, SHUT_WR);
  char response[512] = {0};
  size_t used = 0;
  while(used < sizeof(response) - 1) {
    ssize_t n = recv(fd, response + used, sizeof(response) - 1 - used, 0);
    if(n <= 0) break;
    used += (size_t)n;
    if(memchr(response, '\n', used)) break;
  }
  response[used] = 0;
  close(fd);

  if(!used) {
    LOG_PUTS("ELF loader returned no fetch/launch acknowledgement");
    notify("Afterglow: no response from NexHEN loader");
    return -1;
  }

  LOG_PRINTF("NexHEN loader response: %s", response);
  notify("Afterglow: %s", response);
  return strstr(response, "NEXHEN STUB HANDOFF") ? 0 : -1;
}

"""
    if anchor not in s:
        raise SystemExit("bootstrap main anchor missing")
    s = s.replace(anchor, helper + anchor, 1)

needle2 = '    err = elfldr_spawn(-1, argv, socksrv_elf, socksrv_elf_len);'
replace2 = needle2 + '''
    if(err > 0) {
      LOG_PRINTF("ELF loader server process started with pid %d\\n", err);
      notify("Afterglow: ELF loader server started");
      send_nexhen_uri();
    } else {
      LOG_PRINTF("ELF loader server failed to start: %d\\n", err);
      notify("Afterglow: ELF loader server failed");
    }'''
if "send_nexhen_uri();" not in s:
    if needle2 not in s:
        raise SystemExit("elfldr_spawn anchor missing")
    s = s.replace(needle2, replace2, 1)
p.write_text(s)

# Fix short HTTP reads and reject empty response bodies.
uri_path = Path("uri.c")
u = uri_path.read_text()
old = """  if(!len || status != 200) {
    // TODO: support resources without a content length
    return status;
  }

  if(!(*data = malloc(*len))) {
    return -1;
  }

  if((n = sceHttp2ReadData(ctx->reqId, *data, *len) < 0)) {
    return n;
  }
"""
new = """  if(!len || !*len || status != 200) {
    // TODO: support resources without a content length
    return status;
  }

  if(!(*data = malloc(*len))) {
    return -1;
  }

  size_t off = 0;
  while(off < *len) {
    n = sceHttp2ReadData(ctx->reqId, *data + off, *len - off);
    if(n <= 0) {
      free(*data);
      *data = 0;
      return -1;
    }
    off += (size_t)n;
  }
"""
if new not in u:
    if old not in u:
        raise SystemExit("uri.c HTTP read anchor missing; refusing partial patch")
    u = u.replace(old, new, 1)
    uri_path.write_text(u)

# Add fetch validation, explicit status replies, and detach NexHEN from the
# short-lived URI control socket (the socket is not NexHEN's stdio).
srv_path = Path("socksrv.c")
srv = srv_path.read_text()
if "int uri_payload = 0;" not in srv:
    var_anchor = "  int magic = 0;\n"
    if var_anchor not in srv:
        raise SystemExit("socksrv.c magic variable anchor missing")
    srv = srv.replace(var_anchor, var_anchor + "  int uri_payload = 0;\n", 1)
if "#include <errno.h>" not in srv:
    srv = srv.replace("#include <sys/types.h>\n", "#include <sys/types.h>\n#include <errno.h>\n", 1)
old_uri = """  if(magic == PAYLOAD_MAGIC_FILE || magic == PAYLOAD_MAGIC_HTTP) {
    if(payload_readuri(fd, uri, PATH_MAX)
       || uri_get_content(uri, &buf, &len)) {
      LOG_PERROR("read_uri");
      write(fd, "[elfldr.elf] Error reading URI payload\\n\\r\\0", 41);
    }

  } else if(magic == PAYLOAD_MAGIC_ELF) {"""
new_uri = """  if(magic == PAYLOAD_MAGIC_FILE || magic == PAYLOAD_MAGIC_HTTP) {
    uri_payload = 1;
    if(payload_readuri(fd, uri, PATH_MAX)) {
      LOG_PERROR("read_uri");
      write(fd, "[elfldr.elf] Error reading URI\\n\\r\\0", sizeof("[elfldr.elf] Error reading URI\\n\\r\\0") - 1);
      return;
    }
    LOG_PRINTF("Fetching URI payload: %s\\n", uri);
    if(uri_get_content(uri, &buf, &len)) {
      LOG_PERROR("uri_get_content");
      notify("Afterglow: NexHEN download failed");
      write(fd, "[elfldr.elf] URI download failed\\n\\r\\0", sizeof("[elfldr.elf] URI download failed\\n\\r\\0") - 1);
      return;
    }

  } else if(magic == PAYLOAD_MAGIC_ELF) {"""
if new_uri not in srv:
    if old_uri not in srv:
        raise SystemExit("socksrv.c URI branch anchor missing; refusing partial patch")
    srv = srv.replace(old_uri, new_uri, 1)

old_tail = """  if(buf) {
    if(!(filename = uri_get_filename(uri))) {
      filename = strdup("payload.elf");
    }
    if(!(args = uri_get_param(uri, "args"))) {
      args = strdup("");
    }
    if(payload_spawn(filename, args, fd, buf, len) < 0) {
      write(fd, "[elfldr.elf] Error spawning payload\\n\\r\\0", 38);
    }
    free(filename);
    free(args);
    free(buf);
  }
"""
new_tail = """  if(buf) {
    LOG_PRINTF("Fetched payload: %zu bytes\\n", len);
    notify("Afterglow: downloaded payload (%zu bytes)", len);
    if(len < 4 || buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F'
       || elfldr_sanity_check(buf, len) != 0) {
      LOG_PUTS("ELF sanity check failed");
      notify("Afterglow: downloaded file is not a valid ELF");
      write(fd, "[elfldr.elf] Invalid ELF payload\\n\\r\\0", sizeof("[elfldr.elf] Invalid ELF payload\\n\\r\\0") - 1);
      free(buf);
      return;
    }
    if(!(filename = uri_get_filename(uri))) {
      filename = strdup("payload.elf");
    }
    if(!(args = uri_get_param(uri, "args"))) {
      args = strdup("");
    }
    /* A URI request's sender is a control channel, not NexHEN stdio. */
    pid_t payload_pid = payload_spawn(filename, args, uri_payload ? -1 : fd, buf, len);
    if(payload_pid < 0) {
      LOG_PUTS("Error spawning payload");
      notify("Afterglow: NexHEN ELF launch failed");
      write(fd, "[elfldr.elf] Error spawning payload\\n\\r\\0", 38);
    } else if(uri_payload) {
      char status[128];
      int status_len = snprintf(status, sizeof(status),
                                "NEXHEN STUB HANDOFF pid=%d\\n", payload_pid);
      LOG_PRINTF("NexHEN stub handed off with pid %d\\n", payload_pid);
      notify("Afterglow: NexHEN stub handed off (PID %d)", payload_pid);
      write(fd, status, status_len);
    } else {
      LOG_PRINTF("Nested ELF payload spawned with pid %d\\n", payload_pid);
      notify("Afterglow: NexHEN core ELF launched (PID %d)", payload_pid);
    }
    free(filename);
    free(args);
    free(buf);
  }
"""
if new_tail not in srv:
    if old_tail not in srv:
        raise SystemExit("socksrv.c payload branch anchor missing; refusing partial patch")
    srv = srv.replace(old_tail, new_tail, 1)
# Report every loader connection and identify whether the stub's second-stage
# connection reaches the listener and supplies a raw ELF.
if 'LOG_PRINTF("ELF loader accepted connection' not in srv:
    conn_anchor = '''  if(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval)) < 0) {'''
    conn_diag = '''  struct sockaddr_in peer = {0};
  socklen_t peer_len = sizeof(peer);
  char peer_ip[INET_ADDRSTRLEN] = "unknown";
  if(getpeername(fd, (struct sockaddr *)&peer, &peer_len) == 0) {
    inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));
  }
  LOG_PRINTF("ELF loader accepted connection from %s:%u\\n",
             peer_ip, ntohs(peer.sin_port));
  notify("Afterglow: loader connection from %s", peer_ip);

'''
    if conn_anchor not in srv:
        raise SystemExit("connection diagnostic anchor missing")
    srv = srv.replace(conn_anchor, conn_diag + conn_anchor, 1)

if 'ELF loader received payload magic' not in srv:
    magic_anchor = '''  if(magic == PAYLOAD_MAGIC_FILE || magic == PAYLOAD_MAGIC_HTTP) {'''
    magic_diag = '''  LOG_PRINTF("ELF loader received payload magic 0x%08x\\n", magic);
  if(magic == PAYLOAD_MAGIC_ELF) {
    LOG_PUTS("Nested raw ELF connection received from NexHEN stub");
    notify("Afterglow: NexHEN second-stage ELF received");
  } else if(magic == PAYLOAD_MAGIC_HTTP || magic == PAYLOAD_MAGIC_FILE) {
    LOG_PUTS("URI control request received");
  }

'''
    if magic_anchor not in srv:
        raise SystemExit("payload magic diagnostic anchor missing")
    srv = srv.replace(magic_anchor, magic_diag + magic_anchor, 1)

if 'Afterglow: second-stage ELF read failed' not in srv:
    old = '''    if(elfldr_read(fd, &buf, &len)) {
      LOG_PERROR("elfldr_read");'''
    new = '''    if(elfldr_read(fd, &buf, &len)) {
      LOG_PERROR("elfldr_read");
      notify("Afterglow: second-stage ELF read failed");'''
    if old not in srv:
        raise SystemExit("ELF read diagnostic anchor missing")
    srv = srv.replace(old, new, 1)

srv_path.write_text(srv)

# Instrument fatal stages in elfldr_spawn so the PS4 identifies the exact failure.
elf_path = Path("elfldr.c")
elf = elf_path.read_text()
if '#include "notify.h"' not in elf:
    elf = elf.replace('#include "log.h"\n', '#include "log.h"\n#include "notify.h"\n', 1)
if "#include <errno.h>" not in elf:
    elf = elf.replace("#include <elf.h>\n", "#include <elf.h>\n#include <errno.h>\n", 1)
replacements = [
("""  if((kq = kqueue()) < 0) {
    LOG_PERROR("kqueue");
    return -1;
  }""", """  if((kq = kqueue()) < 0) {
    LOG_PERROR("kqueue");
    notify("Afterglow: NexHEN spawn failed at kqueue");
    return -1;
  }"""),
("""  if(!(stack = malloc(MB(2)))) {
    LOG_PERROR("malloc");
    close(kq);
    return -1;
  }""", """  /* The loader server has a constrained libc heap; map the 2 MB stack. */
  if((stack = mmap(0, MB(2), PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
    LOG_PERROR("mmap");
    notify("Afterglow: NexHEN spawn failed mapping thread stack");
    close(kq);
    return -1;
  }"""),
("""     < 0) {
    LOG_PERROR("rfork_thread");
    free(stack);""", """     < 0) {
    LOG_PERROR("rfork_thread");
    notify("Afterglow: NexHEN spawn failed at rfork_thread");
    free(stack);"""),
("""  if(kevent(kq, &evt, 1, &evt, 1, 0) < 0) {
    LOG_PERROR("kevent");
    free(stack);""", """  if(kevent(kq, &evt, 1, &evt, 1, 0) < 0) {
    LOG_PERROR("kevent");
    notify("Afterglow: NexHEN spawn failed waiting for exec");
    free(stack);"""),
("""    LOG_PERROR("pt_attach");
    kill(pid, SIGKILL);""", """    LOG_PERROR("pt_attach");
    notify("Afterglow: NexHEN spawn failed attaching to process");
    kill(pid, SIGKILL);"""),
("""    LOG_PT_PERROR(pid, "pt_dynlib_process_needed_and_relocate");
    pt_detach(pid, SIGKILL);""", """    LOG_PT_PERROR(pid, "pt_dynlib_process_needed_and_relocate");
    notify("Afterglow: NexHEN spawn failed relocating system libraries");
    pt_detach(pid, SIGKILL);"""),
("""    LOG_PUTS("kernel_dynlib_entry_addr failed");
    pt_detach(pid, SIGKILL);""", """    LOG_PUTS("kernel_dynlib_entry_addr failed");
    notify("Afterglow: NexHEN spawn failed finding entry point");
    pt_detach(pid, SIGKILL);"""),
("""    LOG_PERROR("mdbg_copyout");
    pt_detach(pid, SIGKILL);""", """    LOG_PERROR("mdbg_copyout");
    notify("Afterglow: NexHEN spawn failed reading entry instruction");
    pt_detach(pid, SIGKILL);"""),
("""    LOG_PERROR("pt_continue");
    pt_detach(pid, SIGKILL);""", """    LOG_PERROR("pt_continue");
    notify("Afterglow: NexHEN spawn failed resuming process");
    pt_detach(pid, SIGKILL);"""),
("""    LOG_PERROR("waitpid");
    pt_detach(pid, SIGKILL);""", """    LOG_PERROR("waitpid");
    notify("Afterglow: NexHEN spawn failed waiting for entry breakpoint");
    pt_detach(pid, SIGKILL);"""),
("""  if(elfldr_exec(pid, stdio, elf, elf_size)) {
    kill(pid, SIGKILL);
    return -1;
  }""", """  if(elfldr_exec(pid, stdio, elf, elf_size)) {
    notify("Afterglow: NexHEN spawn failed loading ELF segments or setting registers");
    kill(pid, SIGKILL);
    return -1;
  }"""),
("""  if(mdbg_copyin(pid, &orginstr, brkpoint, sizeof(orginstr))) {
    LOG_PERROR("mdbg_copyin");
    pt_detach(pid, SIGKILL);""", """  if(mdbg_copyin(pid, &orginstr, brkpoint, sizeof(orginstr))) {
    LOG_PERROR("mdbg_copyin");
    notify("Afterglow: NexHEN spawn failed restoring entry instruction");
    pt_detach(pid, SIGKILL);"""),
("""  if(elfldr_set_heap_size(pid, -1)) {
    LOG_PT_PERROR(pid, "pt_dynlib_process_needed_and_relocate");
  }""", """  if(elfldr_set_heap_size(pid, -1)) {
    LOG_PT_PERROR(pid, "pt_dynlib_process_needed_and_relocate");
    notify("Afterglow: NexHEN warning setting process heap size");
  }"""),
("""  if(!(ctx.base_mirror = malloc(ctx.base_size))) {
    LOG_PERROR("malloc");
    return 0;
  }""", """  if(!ctx.base_size) {
    LOG_PUTS("ELF mirror size is zero");
    notify("Afterglow: NexHEN ELF mirror size is zero");
    return 0;
  }

  ctx.base_mirror = mmap(0, ctx.base_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if(ctx.base_mirror == MAP_FAILED) {
    int mirror_errno = errno;
    LOG_PERROR("mmap ELF mirror");
    notify("Afterglow: ELF mirror mmap failed (%zu bytes, errno %d)",
           ctx.base_size, mirror_errno);
    return 0;
  }"""),
("""     == -1) {
    LOG_PT_PERROR(pid, "pt_mmap");
    free(ctx.base_mirror);""", """     == -1) {
    LOG_PT_PERROR(pid, "pt_mmap");
    notify("Afterglow: NexHEN ELF load failed mapping target memory");
    free(ctx.base_mirror);"""),
("""  if(mdbg_copyin(ctx.pid, ctx.base_mirror, ctx.base_addr, ctx.base_size)) {
    LOG_PERROR("mdbg_copyin");
    error = 1;
  }""", """  if(mdbg_copyin(ctx.pid, ctx.base_mirror, ctx.base_addr, ctx.base_size)) {
    LOG_PERROR("mdbg_copyin");
    notify("Afterglow: NexHEN ELF load failed copying segments");
    error = 1;
  }"""),
("""      LOG_PT_PERROR(pid, "pt_mprotect");
      error = 1;""", """      LOG_PT_PERROR(pid, "pt_mprotect");
      notify("Afterglow: NexHEN ELF load failed setting segment permissions");
      error = 1;"""),
("""  if(pt_msync(pid, ctx.base_addr, ctx.base_size, MS_SYNC)) {
    LOG_PT_PERROR(pid, "pt_msync");
    error = 1;
  }""", """  if(pt_msync(pid, ctx.base_addr, ctx.base_size, MS_SYNC)) {
    LOG_PT_PERROR(pid, "pt_msync");
    notify("Afterglow: NexHEN ELF load failed syncing segments");
    error = 1;
  }"""),
("""  if(error) {
    pt_munmap(pid, ctx.base_addr, ctx.base_size);
    return 0;
  }""", """  if(error) {
    notify("Afterglow: NexHEN ELF load aborted after a segment error");
    pt_munmap(pid, ctx.base_addr, ctx.base_size);
    return 0;
  }"""),
("""  if(pt_getregs(pid, &r)) {
    LOG_PERROR("pt_getregs");
    return -1;
  }""", """  if(pt_getregs(pid, &r)) {
    LOG_PERROR("pt_getregs");
    notify("Afterglow: NexHEN exec failed reading process registers");
    return -1;
  }"""),
("""  if(!(entry = elfldr_load(pid, elf))) {
    LOG_PUTS("elfldr_load failed");
    return -1;
  }""", """  if(!(entry = elfldr_load(pid, elf))) {
    LOG_PUTS("elfldr_load failed");
    notify("Afterglow: NexHEN exec failed loading ELF image");
    return -1;
  }"""),
("""  if(pt_setregs(pid, &r)) {
    LOG_PERROR("pt_setregs");
    pt_detach(pid, SIGKILL);""", """  if(pt_setregs(pid, &r)) {
    LOG_PERROR("pt_setregs");
    notify("Afterglow: NexHEN exec failed setting entry registers");
    pt_detach(pid, SIGKILL);"""),
("""  if(elfldr_raise_privileges(pid)) {
    LOG_PUTS("Unable to raise privileges");
    pt_detach(pid, SIGKILL);""", """  if(elfldr_raise_privileges(pid)) {
    LOG_PUTS("Unable to raise privileges");
    notify("Afterglow: NexHEN exec failed setting process privileges");
    pt_detach(pid, SIGKILL);"""),
("""  if(elfldr_prepare_exec(pid, elf)) {
    error = -1;
  }""", """  if(elfldr_prepare_exec(pid, elf)) {
    notify("Afterglow: NexHEN exec preparation failed");
    error = -1;
  }""")

]
for old, new in replacements:
    if new not in elf and old in elf:
        elf = elf.replace(old, new, 1)
# mmap owns both the thread stack and ELF mirror; release each with munmap.
elf = elf.replace("free(stack);", "munmap(stack, MB(2));")
elf = elf.replace("free(ctx.base_mirror);", "munmap(ctx.base_mirror, ctx.base_size);")
elf_path.write_text(elf)

# Instrument the nested ELF stream reader so the PS4 reports the exact
# recv stage and byte count instead of a generic elfldr_read failure.
elf_path = Path("elfldr.c")
elf = elf_path.read_text()
start = elf.find("int\nelfldr_read(int fd, uint8_t **elf, size_t *elf_size) {")
if start < 0:
    raise SystemExit("elfldr_read function start not found")
end = elf.find("\n}\n", start)
if end < 0:
    raise SystemExit("elfldr_read function end not found")
end += 3
new_reader = r"""
int
elfldr_read(int fd, uint8_t **elf, size_t *elf_size) {
  Elf64_Shdr *shdr;
  Elf64_Ehdr ehdr;
  uint8_t *buf;
  uint8_t *bak;
  size_t size;
  off_t shend;
  size_t rem;
  ssize_t got;

  got = recv(fd, &ehdr, sizeof(ehdr), MSG_WAITALL);
  if(got != sizeof(ehdr)) {
    LOG_PRINTF("elfldr_read: ELF header recv got %zd of %zu bytes (errno %d)\n",
               got, sizeof(ehdr), errno);
    notify("Afterglow: ELF header incomplete (%zd/%zu)", got, sizeof(ehdr));
    return -1;
  }

  LOG_PRINTF("elfldr_read: header ok, class %u, machine %u, shoff %llu, shnum %u, shentsize %u\n",
             ehdr.e_ident[EI_CLASS], ehdr.e_machine,
             (unsigned long long)ehdr.e_shoff, ehdr.e_shnum, ehdr.e_shentsize);

  if(ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E'
     || ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F') {
    errno = ENOEXEC;
    notify("Afterglow: second-stage stream is not ELF");
    return -1;
  }

  if(ehdr.e_ident[EI_CLASS] != ELFCLASS64
     || ehdr.e_shentsize != sizeof(Elf64_Shdr)
     || ehdr.e_shnum == 0
     || ehdr.e_shoff > SIZE_MAX
     || ehdr.e_shnum > (SIZE_MAX - (size_t)ehdr.e_shoff) / sizeof(Elf64_Shdr)) {
    errno = ENOEXEC;
    LOG_PUTS("elfldr_read: unsupported or malformed ELF section table");
    notify("Afterglow: malformed second-stage ELF header");
    return -1;
  }

  size = (size_t)ehdr.e_shoff + (size_t)ehdr.e_shnum * sizeof(Elf64_Shdr);
  if(size < sizeof(ehdr)) {
    errno = ENOEXEC;
    notify("Afterglow: invalid second-stage ELF size");
    return -1;
  }

  if(!(buf = malloc(size))) {
    LOG_PERROR("elfldr_read malloc");
    notify("Afterglow: cannot allocate second-stage ELF header");
    return -1;
  }

  memcpy(buf, &ehdr, sizeof(ehdr));
  rem = size - sizeof(ehdr);
  got = recv(fd, buf + sizeof(ehdr), rem, MSG_WAITALL);
  if(got != (ssize_t)rem) {
    LOG_PRINTF("elfldr_read: section table recv got %zd of %zu bytes (errno %d)\n",
               got, rem, errno);
    notify("Afterglow: ELF section table incomplete (%zd/%zu)", got, rem);
    free(buf);
    return -1;
  }

  shend = (off_t)size;
  shdr = (Elf64_Shdr *)(buf + ehdr.e_shoff);
  for(int i = 0; i < ehdr.e_shnum; i++) {
    if(shdr[i].sh_type == SHT_NOBITS) {
      continue;
    }
    if(shdr[i].sh_offset > SIZE_MAX
       || shdr[i].sh_size > SIZE_MAX - (size_t)shdr[i].sh_offset) {
      errno = ENOEXEC;
      free(buf);
      notify("Afterglow: invalid ELF section bounds");
      return -1;
    }
    size_t section_end = (size_t)shdr[i].sh_offset + (size_t)shdr[i].sh_size;
    if(section_end > (size_t)shend) {
      shend = section_end;
    }
  }

  if((size_t)shend <= size) {
    *elf = buf;
    *elf_size = size;
    return 0;
  }

  bak = buf;
  if(!(buf = realloc(buf, (size_t)shend))) {
    free(bak);
    LOG_PERROR("elfldr_read realloc");
    notify("Afterglow: cannot allocate full second-stage ELF");
    return -1;
  }

  rem = (size_t)shend - size;
  got = recv(fd, buf + size, rem, MSG_WAITALL);
  if(got != (ssize_t)rem) {
    LOG_PRINTF("elfldr_read: ELF sections recv got %zd of %zu bytes (errno %d)\n",
               got, rem, errno);
    notify("Afterglow: ELF sections incomplete (%zd/%zu)", got, rem);
    free(buf);
    return -1;
  }

  *elf = buf;
  *elf_size = (size_t)shend;
  LOG_PRINTF("elfldr_read: received complete ELF (%zu bytes)\n", *elf_size);
  notify("Afterglow: second-stage ELF read complete");
  return 0;
}
"""
elf = elf[:start] + new_reader + elf[end:]
elf_path.write_text(elf)

print("Patched bootstrap handshake, HTTP body reads, and payload launch reporting")
