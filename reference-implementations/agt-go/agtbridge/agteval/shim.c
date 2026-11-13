//go:build agteval

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include "acs.h"
#include "_cgo_export.h"

static char *annotate(const char *annotator_name, const char *annotator_json,
                      const char *preliminary_policy_input_json, void *user_data) {
	(void)annotator_json;
	(void)user_data;
	return agtevalAnnotate((char *)annotator_name, (char *)preliminary_policy_input_json);
}

static void free_result(char *ptr, void *user_data) {
	(void)user_data;
	free(ptr);
}

int32_t agteval_register_annotator(AcsBuilder *b, char **err) {
	return acs_builder_register_annotator_dispatcher(b, annotate, free_result, NULL, err);
}

// The path of the file the dynamic loader mapped for AGT's runtime library.
char *agteval_library_path(void) {
#ifdef _WIN32
	HMODULE module;
	if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
	                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
	                       (LPCWSTR)(void *)acs_runtime_evaluate, &module)) {
		return NULL;
	}
	DWORD capacity = MAX_PATH;
	wchar_t *wide = NULL;
	for (;;) {
		wchar_t *next = realloc(wide, capacity * sizeof(wchar_t));
		if (next == NULL) { free(wide); return NULL; }
		wide = next;
		DWORD length = GetModuleFileNameW(module, wide, capacity);
		if (length == 0) { free(wide); return NULL; }
		if (length < capacity) break;
		if (capacity > UINT32_MAX / 2 / sizeof(wchar_t)) { free(wide); return NULL; }
		capacity *= 2;
	}
	int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1, NULL, 0, NULL, NULL);
	char *path = size > 0 ? malloc(size) : NULL;
	if (path != NULL && !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1, path, size, NULL, NULL)) {
		free(path);
		path = NULL;
	}
	free(wide);
	return path;
#else
	Dl_info info;
	if (dladdr((void *)acs_runtime_evaluate, &info) == 0 || info.dli_fname == NULL) {
		return NULL;
	}
	return strdup(info.dli_fname);
#endif
}
