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
#include "jst.h"
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

extern "C" {
  int read_file(const char *filename, char** bufout, size_t* lenout);
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

TEST(general, read_file_directory_input_returns_failure)
{
  char* buffer = NULL;
  size_t length = 0;

  EXPECT_EQ(read_file("//", &buffer, &length), 0);
  EXPECT_EQ(buffer, nullptr);
}

TEST(general, session_start_does_not_modify_cookie_env)
{
  const char* sesid = "jst_sessABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
  char session_file_path[128];
  char cookie[256];

  snprintf(session_file_path, sizeof(session_file_path), "/tmp/%s", sesid);
  FILE* f = fopen(session_file_path, "w");
  ASSERT_NE(f, nullptr);
  fclose(f);

  snprintf(cookie, sizeof(cookie), "a=1; DUKSID=%s; b=2", sesid);
  ASSERT_EQ(setenv("HTTP_COOKIE", cookie, 1), 0);

  duk_context* ctx = duk_create_heap_default();
  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_session_module_open, 0);
  duk_call(ctx, 0);
  duk_put_global_string(ctx, "ccsp_session");

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "destroy");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  duk_pop_2(ctx);

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "start");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  ASSERT_TRUE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  const char* cookie_after = getenv("HTTP_COOKIE");
  ASSERT_NE(cookie_after, nullptr);
  EXPECT_STREQ(cookie_after, cookie);

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "destroy");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  duk_pop_2(ctx);

  duk_destroy_heap(ctx);

  remove(session_file_path);
}

TEST(general, session_start_rejects_invalid_session_prefix)
{
  const char* invalid_sesid = "bad_prefABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
  char session_file_path[128];
  char cookie[256];

  snprintf(session_file_path, sizeof(session_file_path), "/tmp/%s", invalid_sesid);
  FILE* f = fopen(session_file_path, "w");
  ASSERT_NE(f, nullptr);
  fclose(f);

  snprintf(cookie, sizeof(cookie), "DUKSID=%s", invalid_sesid);
  ASSERT_EQ(setenv("HTTP_COOKIE", cookie, 1), 0);

  duk_context* ctx = duk_create_heap_default();
  ASSERT_NE(ctx, nullptr);

  duk_push_c_function(ctx, ccsp_session_module_open, 0);
  duk_call(ctx, 0);
  duk_put_global_string(ctx, "ccsp_session");

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "destroy");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  duk_pop_2(ctx);

  duk_get_global_string(ctx, "ccsp_session");
  duk_get_prop_string(ctx, -1, "start");
  ASSERT_EQ(duk_pcall(ctx, 0), DUK_EXEC_SUCCESS);
  EXPECT_FALSE(duk_get_boolean(ctx, -1));
  duk_pop_2(ctx);

  duk_destroy_heap(ctx);

  remove(session_file_path);
}

int main(int argc, char* argv[])
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
