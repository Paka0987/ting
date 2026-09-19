#include "common.h"
#include "device_compat.h"

#include <sys/system_properties.h>

static int read_prop(const char *name, char *out, size_t out_sz) {
  if (!name || !out || out_sz == 0) {
    return -1;
  }

  char buf[PROP_VALUE_MAX];
  int n = __system_property_get(name, buf);
  if (n <= 0) {
    out[0] = '\0';
    return -1;
  }

  if ((size_t)n >= out_sz) {
    n = (int)out_sz - 1;
  }
  memcpy(out, buf, (size_t)n);
  out[n] = '\0';
  return n;
}

static int read_first_line(const char *path, char *out, size_t out_sz) {
  if (!path || !out || out_sz == 0) {
    return -1;
  }

  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    out[0] = '\0';
    return -1;
  }

  ssize_t n = read(fd, out, out_sz - 1);
  int saved_errno = errno;
  close(fd);

  if (n <= 0) {
    out[0] = '\0';
    errno = saved_errno;
    return -1;
  }

  out[n] = '\0';
  char *nl = strpbrk(out, "\r\n");
  if (nl) {
    *nl = '\0';
  }
  return (int)n;
}

static int read_selinux_enforce(void) {
  char buf[32];
  if (read_first_line("/sys/fs/selinux/enforce", buf, sizeof(buf)) < 0) {
    return -1;
  }
  if (buf[0] == '0' && buf[1] == '\0') {
    return 0;
  }
  if (buf[0] == '1' && buf[1] == '\0') {
    return 1;
  }
  return -1;
}

static int read_selinux_policyvers(void) {
  char buf[32];
  if (read_first_line("/sys/fs/selinux/policyvers", buf, sizeof(buf)) < 0) {
    return -1;
  }

  char *end = NULL;
  errno = 0;
  long v = strtol(buf, &end, 10);
  if (errno != 0 || end == buf || *end != '\0' || v < 0 || v > 1000) {
    return -1;
  }
  return (int)v;
}

static void read_proc_context(char *out, size_t out_sz) {
  if (read_first_line("/proc/self/attr/current", out, out_sz) < 0) {
    snprintf(out, out_sz, "unavailable");
  }
}

int device_compat_check(void) {
  struct utsname uts;
  memset(&uts, 0, sizeof(uts));

  int uname_ok = uname(&uts) == 0;

  char incremental[PROP_VALUE_MAX];
  char model[PROP_VALUE_MAX];
  char release[PROP_VALUE_MAX];
  char board[PROP_VALUE_MAX];

  read_prop("ro.build.version.incremental", incremental,
            sizeof(incremental));
  read_prop("ro.product.model", model, sizeof(model));
  read_prop("ro.build.version.release", release, sizeof(release));
  read_prop("ro.board.platform", board, sizeof(board));

  int selinux = read_selinux_enforce();
  int policyvers = read_selinux_policyvers();

  char context[128];
  read_proc_context(context, sizeof(context));

  pr_info("compat: kernel=%s release=%s incremental=%s model=%s board=%s\n",
          uname_ok ? uts.release : "unavailable",
          release[0] ? release : "unavailable",
          incremental[0] ? incremental : "unavailable",
          model[0] ? model : "unavailable",
          board[0] ? board : "unavailable");

  pr_info("compat: selinux=%s policyvers=%d context=%s\n",
          selinux == 1 ? "enforcing" :
          selinux == 0 ? "permissive/disabled" : "unavailable",
          policyvers,
          context);

  /*
   * The supplied 2.7 device is:
   *   kernel      5.10.246-gd7102a837402
   *   incremental 52433670036000520
   *   model       Quest 3
   *
   * We recognize it explicitly, but do not substitute unverified kernel
   * offsets. The existing target remains tied to 52168470043600520.
   */
  if (incremental[0] &&
      strcmp(incremental, "52433670036000520") == 0) {
    pr_warning(
        "compat: Quest 3 2.7 target detected (incremental %s).\n",
        incremental);
    pr_warning(
        "compat: existing target offsets are for 52168470043600520; "
        "2.7 kernel/SELinux offsets are not verified.\n");
    pr_error(
        "compat: refusing to enter the kernel-manipulation path on this "
        "unverified target.\n");
    return 0;
  }

  return 1;
}
