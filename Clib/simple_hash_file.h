/*
 * simple_hash_file.h - sequential file reading for SIMPLE_HASH file digests.
 *
 * One small API with a Win32 and a POSIX body. The path comes from NATIVE_STRING,
 * so it is UTF-16 on Windows and UTF-8 elsewhere; each body takes it as it arrives.
 *
 *   shf_open   handle for reading, or NULL
 *   shf_read   bytes read, 0 at end of file, -1 on error
 *   shf_close  release the handle
 */
#ifndef SIMPLE_HASH_FILE_H
#define SIMPLE_HASH_FILE_H

#if defined(_WIN32) || defined(EIF_WINDOWS)

#include <windows.h>

static void *shf_open (void *a_name)
{
	/* Others may still read, write or delete the file while it is hashed. */
	HANDLE h = CreateFileW ((LPCWSTR) a_name, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	return (h == INVALID_HANDLE_VALUE) ? NULL : (void *) h;
}

static int shf_read (void *a_handle, void *a_buffer, int a_count)
{
	DWORD got = 0;
	if (!ReadFile ((HANDLE) a_handle, (LPVOID) a_buffer, (DWORD) a_count, &got, NULL)) {
		return -1;
	}
	return (int) got;
}

static void shf_close (void *a_handle)
{
	CloseHandle ((HANDLE) a_handle);
}

#else /* POSIX */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

/* A descriptor can be 0, so the handle is descriptor + 1 and NULL can mean failure. */

static void *shf_open (void *a_name)
{
	int fd;
	do {
		fd = open ((const char *) a_name, O_RDONLY | O_CLOEXEC);
	} while (fd < 0 && errno == EINTR);
	return (fd < 0) ? NULL : (void *) (intptr_t) (fd + 1);
}

static int shf_read (void *a_handle, void *a_buffer, int a_count)
{
	int fd = (int) ((intptr_t) a_handle - 1);
	ssize_t got;
	do {
		got = read (fd, a_buffer, (size_t) a_count);
	} while (got < 0 && errno == EINTR);
	return (int) got;
}

static void shf_close (void *a_handle)
{
	close ((int) ((intptr_t) a_handle - 1));
}

#endif

#endif /* SIMPLE_HASH_FILE_H */
