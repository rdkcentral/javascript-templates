/*
 If not stated otherwise in this file or this component's Licenses.txt file the
 following copyright and licenses apply:

 Copyright 2018 RDK Management

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#include "gtest/gtest.h"
#include <cstdio>
#include <fstream>
#include <string>
#include <unistd.h>

extern "C" {
#include "jst.h"
duk_ret_t ccsp_functions_module_open(duk_context *ctx);
}

class DuktapeCtxGuard {
public:
  DuktapeCtxGuard() : ctx_(duk_create_heap_default()) {
  }

  ~DuktapeCtxGuard() {
    if (ctx_) {
      duk_destroy_heap(ctx_);
    }
  }

  duk_context* get() const {
    return ctx_;
  }

private:
  duk_context* ctx_;
};

static bool call_openssl_verify_with_cert(duk_context* ctx,
                                          const char* filepath,
                                          const char* token,
                                          const char* signature_base64url)
{
  duk_get_global_string(ctx, "ccsp");
  duk_get_prop_string(ctx, -1, "openssl_verify_with_cert");
  duk_push_string(ctx, filepath);
  duk_push_string(ctx, token);
  duk_push_string(ctx, signature_base64url);
  duk_push_string(ctx, "RS256");

  if (duk_pcall(ctx, 4) != DUK_EXEC_SUCCESS) {
    duk_pop_2(ctx);
    return false;
  }

  bool ret = duk_get_boolean(ctx, -1);
  duk_pop_2(ctx);
  return ret;
}

static bool call_exec_and_get_boolean_result(duk_context* ctx,
                                             const char* command,
                                             bool* result)
{
  duk_get_global_string(ctx, "ccsp");
  duk_get_prop_string(ctx, -1, "exec");
  duk_push_string(ctx, command);

  if (duk_pcall(ctx, 1) != DUK_EXEC_SUCCESS) {
    duk_pop_2(ctx);
    return false;
  }

  if (!duk_is_boolean(ctx, -1)) {
    duk_pop_2(ctx);
    return false;
  }

  *result = duk_get_boolean(ctx, -1) != 0;
  duk_pop_2(ctx);
  return true;
}

static std::string create_temp_public_key_file()
{
  static const char kPublicKeyPem[] =
      "-----BEGIN PUBLIC KEY-----\n"
      "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALeJ8V+RaHcRUW2KIiMzFxLpy0X58F3R\n"
      "o63eNbUsVTNff7kwh28ykVfoCENKz7LxyzKDn5XxhxL7sRKqzZo4PM8CAwEAAQ==\n"
      "-----END PUBLIC KEY-----\n";

  char tempTemplate[] = "/tmp/jst_pubkey_XXXXXX";
  int fd = mkstemp(tempTemplate);
  if (fd < 0) {
    return std::string();
  }
  close(fd);

  std::ofstream out(tempTemplate, std::ios::out | std::ios::trunc);
  if (!out.is_open()) {
    return std::string();
  }

  out << kPublicKeyPem;
  out.close();

  return std::string(tempTemplate);
}

TEST(openssl_verify_with_cert, handles_empty_filepath_without_crash)
{
  DuktapeCtxGuard guard;
  duk_context* ctx = guard.get();

  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_functions_module_open, 0);
  duk_call(ctx, 0);
  duk_put_global_string(ctx, "ccsp");

  EXPECT_FALSE(call_openssl_verify_with_cert(ctx, "", "test-token", "AQ"));
}

TEST(openssl_verify_with_cert, handles_short_filepath_without_crash)
{
  DuktapeCtxGuard guard;
  duk_context* ctx = guard.get();

  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_functions_module_open, 0);
  duk_call(ctx, 0);
  duk_put_global_string(ctx, "ccsp");

  EXPECT_FALSE(call_openssl_verify_with_cert(ctx, "f", "test-token", "AQ"));
}

TEST(openssl_verify_with_cert, rejects_invalid_signature_with_file_uri)
{
  DuktapeCtxGuard guard;
  duk_context* ctx = guard.get();

  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_functions_module_open, 0);
  duk_call(ctx, 0);
  duk_put_global_string(ctx, "ccsp");

  std::string keyPath = create_temp_public_key_file();
  ASSERT_FALSE(keyPath.empty());

  std::string fileUri = std::string("file://") + keyPath;
  EXPECT_FALSE(call_openssl_verify_with_cert(ctx, fileUri.c_str(), "tokendata", "AQ"));

  std::remove(keyPath.c_str());
}

TEST(exec, rejects_shell_metacharacters)
{
  DuktapeCtxGuard guard;
  duk_context* ctx = guard.get();

  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_functions_module_open, 0);
  duk_call(ctx, 0);
  duk_put_global_string(ctx, "ccsp");

  bool execResult = true;
  ASSERT_TRUE(call_exec_and_get_boolean_result(ctx, "echo hello; id", &execResult));
  EXPECT_FALSE(execResult);
}