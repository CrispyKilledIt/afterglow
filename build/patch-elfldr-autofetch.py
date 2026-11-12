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
      "nexHEN.-rc6-codxelf.elf\n";
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
  return strstr(response, "NEXHEN STARTED") ? 0 : -1;
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
    srv = srv.replace(var_anchor, var_anchor + "  int uri_payload = 0;\\n", 1)
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
      write(fd, "[elfldr.elf] Error reading URI\\n\\r\\0", 34);
      return;
    }
    LOG_PRINTF("Fetching URI payload: %s\\n", uri);
    if(uri_get_content(uri, &buf, &len)) {
      LOG_PERROR("uri_get_content");
      notify("Afterglow: NexHEN download failed");
      write(fd, "[elfldr.elf] URI download failed\\n\\r\\0", 38);
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
    /* A URI request's sender is a control channel, not NexHEN stdio. */
    pid_t payload_pid = payload_spawn(filename, args, uri_payload ? -1 : fd, buf, len);
    if(payload_pid < 0) {
      LOG_PUTS("Error spawning payload");
      notify("Afterglow: NexHEN ELF launch failed");
      write(fd, "[elfldr.elf] Error spawning payload\\n\\r\\0", 38);
    } else {
      char status[128];
      int status_len = snprintf(status, sizeof(status),
                                "NEXHEN STARTED pid=%d\\n", payload_pid);
      LOG_PRINTF("Payload spawned with pid %d\\n", payload_pid);
      notify("Afterglow: NexHEN started (PID %d)", payload_pid);
      write(fd, status, status_len);
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
srv_path.write_text(srv)

print("Patched bootstrap handshake, HTTP body reads, and payload launch reporting")
