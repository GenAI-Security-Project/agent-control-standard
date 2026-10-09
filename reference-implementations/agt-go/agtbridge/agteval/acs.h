// The part of AGT's C ABI (policy-engine/core/src/ffi.rs at the commit
// agt-native.lock pins, MIT licensed) the AGT evaluator calls. AGT ships no
// C header, so these declarations are written from that file. Strings are NUL-terminated
// UTF-8; a string AGT returns is released with acs_free_string, and a string
// the host returns from a callback is released with the host's free callback.

#ifndef AGTEVAL_ACS_H
#define AGTEVAL_ACS_H

#include <stdint.h>

#ifdef _WIN32
#define ACS_API __declspec(dllimport)
#else
#define ACS_API
#endif

typedef struct AcsBuilder AcsBuilder;
typedef struct AcsRuntime AcsRuntime;

typedef void (*AcsFreeResultCallback)(char *ptr, void *user_data);
typedef char *(*AcsAnnotatorCallback)(const char *annotator_name,
                                      const char *annotator_json,
                                      const char *preliminary_policy_input_json,
                                      void *user_data);

ACS_API AcsBuilder *acs_builder_from_path(const char *path, char **err);
ACS_API int32_t acs_builder_register_annotator_dispatcher(AcsBuilder *b,
                                                  AcsAnnotatorCallback cb,
                                                  AcsFreeResultCallback free_result,
                                                  void *user_data, char **err);
ACS_API int32_t acs_builder_enable_default_policy_dispatcher(AcsBuilder *b, char **err);
ACS_API void acs_builder_free(AcsBuilder *b);
ACS_API AcsRuntime *acs_builder_build(AcsBuilder *b, char **err);
ACS_API char *acs_runtime_evaluate(const AcsRuntime *r, const char *request_json, char **err);
ACS_API char *acs_runtime_policy_labels(const AcsRuntime *r, char **err);
ACS_API void acs_runtime_free(AcsRuntime *r);
ACS_API void acs_free_string(char *s);

#endif
