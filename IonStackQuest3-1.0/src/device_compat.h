#ifndef DEVICE_COMPAT_H
#define DEVICE_COMPAT_H

/*
 * Device compatibility checks.
 *
 * This layer deliberately does not derive or guess kernel exploit offsets.
 * It identifies the running Quest build and prevents an unverified target
 * from entering the existing kernel-manipulation path.
 */

int device_compat_check(void);

#endif
