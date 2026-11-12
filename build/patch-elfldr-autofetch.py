#!/usr/bin/env python3
"""Patch upstream elfldr bootstrap to fetch NexHEN through elfldr's native URI protocol."""
from pathlib import Path

p = Path("bootstrap-elf.c")
s = p.read_text()
needle = '#include <signal.h>\n'
addition = '''#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
'''
if "static int\nsend_nexhen_uri" not in s:
    if needle not in s:
        raise SystemExit("bootstrap-elf.c include anchor missing")
    s = s.replace(needle, needle + addition, 1)
    anchor = 'int\nmain(void) {'
    helper = r"""
/* Send a newline-terminated HTTP(S) URI to elfldr's raw TCP socket.
 * elfldr recognizes the first four bytes "http" as its URI protocol. */
static int
send_nexhen_uri(void) {
  static const char uri[] =
      "https://raw.githubusercontent.com/CrispyKilledIt/afterglow/50ee030c6738e43301f852abbaf74f332b64c3d7/"
      "nexHEN.-rc6-codxelf.elf\n";
  struct sockaddr_in addr = {0};
  int fd = -1;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(9021);
  if(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
    return -1;
  }

  /* elfldr_spawn() returns after creating the server process; allow it to bind. */
  for(int i = 0; i < 40; i++) {
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
    return -1;
  }

  size_t off = 0;
  while(off < sizeof(uri) - 1) {
    ssize_t n = send(fd, uri + off, sizeof(uri) - 1 - off, 0);
    if(n <= 0) {
      close(fd);
      LOG_PUTS("Failed sending NexHEN URI to ELF loader");
      return -1;
    }
    off += (size_t)n;
  }

  close(fd);
  LOG_PUTS("NexHEN URI handed to ELF loader");
  return 0;
}

"""
    if anchor not in s:
        raise SystemExit("bootstrap main anchor missing")
    s = s.replace(anchor, helper + anchor, 1)
# call after elfldr_spawn has started child, before restoring credentials
needle2 = '    err = elfldr_spawn(-1, argv, socksrv_elf, socksrv_elf_len);'
replace2 = needle2 + '\n    if(err > 0) {\n      send_nexhen_uri();\n    }'
if "send_nexhen_uri();" not in s:
    if needle2 not in s:
        raise SystemExit("elfldr_spawn anchor missing")
    s = s.replace(needle2, replace2, 1)
p.write_text(s)

# The upstream HTTP reader requested the entire content length only once and
# used a precedence-broken comparison that never detected short reads.
# Read until the advertised length is complete, failing closed on EOF/errors.
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
    print("Patched uri.c: read full HTTP response body")

# Add server-side evidence for URL fetch and ELF launch to the PS4 kernel log.
srv_path = Path("socksrv.c")
srv = srv_path.read_text()
old2 = """  if(buf) {
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
new2 = """  if(buf) {
    LOG_PRINTF("Fetched payload: %zu bytes\\n", len);
    if(magic == PAYLOAD_MAGIC_ELF && elfldr_sanity_check(buf, len)) {
      LOG_PUTS("ELF sanity check failed");
      write(fd, "[elfldr.elf] Invalid ELF payload\\n\\r\\0", 37);
      free(buf);
      return;
    }
    if(!(filename = uri_get_filename(uri))) {
      filename = strdup("payload.elf");
    }
    if(!(args = uri_get_param(uri, "args"))) {
      args = strdup("");
    }
    pid_t payload_pid = payload_spawn(filename, args, fd, buf, len);
    if(payload_pid < 0) {
      LOG_PUTS("Error spawning payload");
      write(fd, "[elfldr.elf] Error spawning payload\\n\\r\\0", 38);
    } else {
      LOG_PRINTF("Payload spawned with pid %d\\n", payload_pid);
    }
    free(filename);
    free(args);
    free(buf);
  }
"""
if new2 not in srv:
    if old2 not in srv:
        raise SystemExit("socksrv.c payload anchor missing; refusing partial patch")
    srv = srv.replace(old2, new2, 1)
    srv_path.write_text(srv)
    print("Patched socksrv.c: log fetch size, validate ELF, log spawn result")


print("Patched bootstrap-elf.c")
