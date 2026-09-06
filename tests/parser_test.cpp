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
#include <string>
#include <fstream>
#include <streambuf>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "jst.h"
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

extern "C" {
  duk_ret_t ccsp_post_module_open(duk_context *ctx);
  duk_ret_t ccsp_session_module_open(duk_context *ctx);
}

using namespace std;

class BufferFreer
{
public:
  BufferFreer(char* buffer) : buffer_(buffer) {
  }
  ~BufferFreer() {
    if(buffer_)
      free(buffer_);
  }
private:
  char* buffer_;
};

class EnvVarGuard
{
public:
  explicit EnvVarGuard(const char* name)
      : name_(name), had_value_(false)
  {
    const char* value = getenv(name_);
    if (value)
    {
      old_value_ = value;
      had_value_ = true;
    }
  }

  ~EnvVarGuard()
  {
    if (had_value_)
      setenv(name_, old_value_.c_str(), 1);
    else
      unsetenv(name_);
  }

  void set(const char* value)
  {
    if (value)
      setenv(name_, value, 1);
    else
      unsetenv(name_);
  }

private:
  const char* name_;
  std::string old_value_;
  bool had_value_;
};

class StdinRedirectGuard
{
public:
  StdinRedirectGuard(const char* data, size_t length)
      : temp_(tmpfile()), original_fd_(-1), active_(false)
  {
    if (!temp_)
      return;

    if (fwrite(data, 1, length, temp_) != length)
      return;

    fflush(temp_);
    rewind(temp_);

    original_fd_ = dup(fileno(stdin));
    if (original_fd_ < 0)
      return;

    if (dup2(fileno(temp_), fileno(stdin)) < 0)
      return;

    active_ = true;
  }

  ~StdinRedirectGuard()
  {
    if (original_fd_ >= 0)
    {
      dup2(original_fd_, fileno(stdin));
      close(original_fd_);
    }

    if (temp_)
      fclose(temp_);
  }

  bool is_active() const
  {
    return active_;
  }

private:
  FILE* temp_;
  int original_fd_;
  bool active_;
};

static std::string makeValidSessionId(char fill)
{
  return std::string("jst_sess0") + std::string(31, fill);
}

static string getFieldValue(const string& input, const string& key)
{
  string pattern = key + "=";
  size_t start = input.find(pattern);
  if (start == string::npos)
    return "";

  start += pattern.length();
  size_t end = input.find('&', start);
  if (end == string::npos)
    return input.substr(start);

  return input.substr(start, end - start);
}

int recurseDirectory(const string& path, vector<string>& files, const string& match)
{
  DIR *dir;
  struct dirent *ent;

  //printf("enter %s\n", path.c_str());
  if ((dir = opendir (path.c_str())) != NULL)
  {
    while ((ent = readdir (dir)) != NULL)
    {
      if(ent->d_type == DT_DIR && ent->d_name[0] != '.')
      {
        string subdir = path + ent->d_name + "/";
        if(recurseDirectory(subdir, files, match))
          return 1;
      }
      else if(ent->d_type == DT_REG)
      {
        string file = ent->d_name;
        if(!match.empty())
        {
          if(file.length() >= match.length())
          {
             if(file.substr(file.length() - match.length()) == match)
              files.push_back(path + ent->d_name);
          }
        }
        else
          files.push_back(path + ent->d_name);
      }
    };
    closedir (dir);
    return 0;
  }
  else
  {
    perror ("error");
    return 1;
  }
}

TEST(general, parser) {
  vector<string> files;
  char* inBuffer;
  size_t inLength;
  size_t rc;
  ASSERT_EQ(recurseDirectory("./", files, ".jst"), 0);
  for(auto file: files) {
    string parsedFile = file + ".parsed";
    struct stat sb;
    if(stat(parsedFile.c_str(), &sb)==0) {
      fprintf(stderr, "\n\n%s\n",file.c_str());
      rc = load_template_file(file.c_str(), &inBuffer, &inLength, 1);
      if(rc == 0)
        fprintf(stderr, "load_template_file %s failed\n", file.c_str());
      ASSERT_NE(rc,0);
      BufferFreer freer(inBuffer);
      std::ifstream foutput(parsedFile.c_str());
      EXPECT_TRUE(foutput.is_open());
      std::string soutput((std::istreambuf_iterator<char>(foutput)), std::istreambuf_iterator<char>());
      EXPECT_EQ(strcmp(inBuffer, soutput.c_str()), 0);
    }
  }
}

TEST(general, session_create_multiple_calls_succeed)
{
  duk_context* ctx = duk_create_heap_default();
  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_session_module_open, 0);
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  duk_put_global_string(ctx, "ccsp_session");

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "create");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_TRUE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "create");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_TRUE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "destroy");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_TRUE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_destroy_heap(ctx);
}

TEST(general, multipart_file_only_request_leaves_post_unset)
{
  const string boundary = "----jstBoundary123";
  const string body =
      string("--") + boundary + "\r\n"
      + "Content-Disposition: form-data; name=\"upload\"; filename=\"config.bin\"\r\n"
      + "Content-Type: application/octet-stream\r\n"
      + "\r\n"
      + "abc123\r\n"
      + string("--") + boundary + "--\r\n";
  const string content_type = "multipart/form-data; boundary=" + boundary;
  const string content_length = to_string(body.size());

  EnvVarGuard content_type_guard("CONTENT_TYPE");
  EnvVarGuard content_length_guard("CONTENT_LENGTH");
  content_type_guard.set(content_type.c_str());
  content_length_guard.set(content_length.c_str());

  StdinRedirectGuard stdin_guard(body.c_str(), body.size());
  ASSERT_TRUE(stdin_guard.is_active());

  duk_context* ctx = duk_create_heap_default();
  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_post_module_open, 0);
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  duk_put_global_string(ctx, "ccsp_post");

  duk_get_global_string(ctx, "ccsp_post");
  duk_get_prop_string(ctx, -1, "getFiles");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  ASSERT_TRUE(duk_is_string(ctx, -1));
  string files_value = duk_get_string(ctx, -1);
  duk_pop_2(ctx);

  const string tmp_name = getFieldValue(files_value, "tmp_name");
  if (!tmp_name.empty())
    remove(tmp_name.c_str());

  duk_get_global_string(ctx, "ccsp_post");
  duk_get_prop_string(ctx, -1, "getPost");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_FALSE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_destroy_heap(ctx);
}

TEST(general, session_create_destroy_cycle_and_id_format)
{
  duk_context* ctx = duk_create_heap_default();
  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_session_module_open, 0);
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  duk_put_global_string(ctx, "ccsp_session");

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "create");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_TRUE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "getId");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  const char* first_id = duk_get_string(ctx, -1);
  ASSERT_NE(first_id, nullptr);
  EXPECT_EQ(strlen(first_id), 40u);
  EXPECT_EQ(strncmp(first_id, "jst_sess", 8), 0);

  char first_session_file[128] = {0};
  snprintf(first_session_file, sizeof(first_session_file), "/tmp/%s", first_id);
  duk_pop_2(ctx);

  FILE* stale = fopen(first_session_file, "w");
  ASSERT_NE(stale, nullptr);
  fclose(stale);
  ASSERT_EQ(access(first_session_file, F_OK), 0);

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "create");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_TRUE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  EXPECT_NE(access(first_session_file, F_OK), 0);

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "destroy");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_TRUE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_destroy_heap(ctx);
}

TEST(general, session_is_secure_detects_request_scheme)
{
  EnvVarGuard https_guard("HTTPS");
  EnvVarGuard request_scheme_guard("REQUEST_SCHEME");
  EnvVarGuard ssl_protocol_guard("SSL_PROTOCOL");
  https_guard.set(nullptr);
  request_scheme_guard.set(nullptr);
  ssl_protocol_guard.set(nullptr);

  duk_context* ctx = duk_create_heap_default();
  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_session_module_open, 0);
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  duk_put_global_string(ctx, "ccsp_session");

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "isSecure");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_FALSE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  https_guard.set("on");
  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "isSecure");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_TRUE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  https_guard.set("off");
  request_scheme_guard.set("https");
  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "isSecure");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_TRUE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  request_scheme_guard.set("http");
  ssl_protocol_guard.set("TLSv1.3");
  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "isSecure");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_TRUE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  ssl_protocol_guard.set(nullptr);
  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "isSecure");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_FALSE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_destroy_heap(ctx);
}

TEST(general, session_start_accepts_existing_valid_cookie_id)
{
  EnvVarGuard cookie_guard("HTTP_COOKIE");
  const std::string session_id = makeValidSessionId('A');
  const std::string cookie = "DUKSID=" + session_id;
  const std::string session_file = "/tmp/" + session_id;

  FILE* file = fopen(session_file.c_str(), "w");
  ASSERT_NE(file, nullptr);
  fclose(file);

  cookie_guard.set(cookie.c_str());

  duk_context* ctx = duk_create_heap_default();
  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_session_module_open, 0);
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  duk_put_global_string(ctx, "ccsp_session");

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "start");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_TRUE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "getId");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  ASSERT_TRUE(duk_is_string(ctx, -1));
  EXPECT_STREQ(duk_get_string(ctx, -1), session_id.c_str());
  duk_pop_2(ctx);

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "destroy");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_TRUE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_destroy_heap(ctx);
}

TEST(general, session_start_rejects_invalid_cookie_ids)
{
  const std::vector<std::string> cookies = {
      "DUKSID=jst_sessshort",
      "DUKSID=jst_sessAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/",
      "DUKSID=jst_sesAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "DUKSID=jst_sessAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!",
      "DUKSID=jst_sessAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAextra"};

  for (const std::string& cookie : cookies)
  {
    EnvVarGuard cookie_guard("HTTP_COOKIE");
    cookie_guard.set(cookie.c_str());

    duk_context* ctx = duk_create_heap_default();
    ASSERT_NE(ctx, nullptr);

    duk_push_c_function(ctx, ccsp_session_module_open, 0);
    ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
    duk_put_global_string(ctx, "ccsp_session");

    duk_get_global_string(ctx, "ccsp_session");
    duk_get_prop_string(ctx, -1, "start");
    ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
    EXPECT_FALSE(duk_get_boolean(ctx, -1)) << "cookie was unexpectedly accepted: " << cookie;
    duk_pop_2(ctx);

    duk_get_global_string(ctx, "ccsp_session");
    duk_get_prop_string(ctx, -1, "getStatus");
    ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
    EXPECT_FALSE(duk_get_boolean(ctx, -1));
    duk_pop_2(ctx);

    duk_destroy_heap(ctx);
  }
}

TEST(general, session_start_rejects_missing_cookie)
{
  EnvVarGuard cookie_guard("HTTP_COOKIE");
  cookie_guard.set(nullptr);

  duk_context* ctx = duk_create_heap_default();
  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_session_module_open, 0);
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  duk_put_global_string(ctx, "ccsp_session");

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "start");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_FALSE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "getStatus");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_FALSE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_destroy_heap(ctx);
}

TEST(general, session_start_rejects_cookie_from_other_scheme)
{
  EnvVarGuard cookie_guard("HTTP_COOKIE");
  EnvVarGuard https_guard("HTTPS");
  const std::string session_id = makeValidSessionId('D');
  const std::string cookie = "DUKSID=" + session_id;
  const std::string session_file = "/tmp/" + session_id;

  FILE* file = fopen(session_file.c_str(), "w");
  ASSERT_NE(file, nullptr);
  fclose(file);
  cookie_guard.set(cookie.c_str());
  https_guard.set("on");

  duk_context* ctx = duk_create_heap_default();
  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_session_module_open, 0);
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  duk_put_global_string(ctx, "ccsp_session");

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "start");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_FALSE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  EXPECT_EQ(access(session_file.c_str(), F_OK), 0);
  unlink(session_file.c_str());
  duk_destroy_heap(ctx);
}

TEST(general, session_get_data_without_session_returns_empty_object)
{
  EnvVarGuard cookie_guard("HTTP_COOKIE");
  cookie_guard.set(nullptr);

  duk_context* ctx = duk_create_heap_default();
  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_session_module_open, 0);
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  duk_put_global_string(ctx, "ccsp_session");

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "getData");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_TRUE(duk_is_object(ctx, -1));
  duk_pop_2(ctx);

  duk_destroy_heap(ctx);
}

TEST(general, session_destroy_without_session_returns_false)
{
  EnvVarGuard cookie_guard("HTTP_COOKIE");
  cookie_guard.set(nullptr);

  duk_context* ctx = duk_create_heap_default();
  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_session_module_open, 0);
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  duk_put_global_string(ctx, "ccsp_session");

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "destroy");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_FALSE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_destroy_heap(ctx);
}

TEST(general, session_start_rejects_expired_session)
{
  EnvVarGuard cookie_guard("HTTP_COOKIE");
  const std::string session_id = makeValidSessionId('C');
  const std::string cookie = "DUKSID=" + session_id;
  const std::string session_file = "/tmp/" + session_id;

  FILE* file = fopen(session_file.c_str(), "w");
  ASSERT_NE(file, nullptr);
  fclose(file);
  cookie_guard.set(cookie.c_str());

  duk_context* ctx = duk_create_heap_default();
  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_session_module_open, 0);
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  duk_put_global_string(ctx, "ccsp_session");

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "start");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_TRUE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  ASSERT_EQ(unlink(session_file.c_str()), 0);

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "start");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_FALSE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "getStatus");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_FALSE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_destroy_heap(ctx);
}

TEST(general, session_start_rejects_missing_session_file)
{
  EnvVarGuard cookie_guard("HTTP_COOKIE");
  const std::string session_id = makeValidSessionId('B');
  const std::string cookie = "DUKSID=" + session_id;
  const std::string session_file = "/tmp/" + session_id;

  unlink(session_file.c_str());
  cookie_guard.set(cookie.c_str());

  duk_context* ctx = duk_create_heap_default();
  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_session_module_open, 0);
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  duk_put_global_string(ctx, "ccsp_session");

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "start");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_FALSE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "getStatus");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_FALSE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_destroy_heap(ctx);
}

int main(int argc, char* argv[])
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
