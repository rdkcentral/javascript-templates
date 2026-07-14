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
#include <cstring>
#include "jst.h"
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

extern "C" {
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

int main(int argc, char* argv[])
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
