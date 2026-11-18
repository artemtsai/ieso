/**
 * @file proc_info_test.cpp
 * @brief libproc/sysctl helpers against the test process itself.
 */
#include <gtest/gtest.h>
#include <unistd.h>

#include "ieso/macos/proc_info.hpp"

using namespace ieso;
using namespace ieso::macos;

/// Our own pid is listed, has a path, task info and open FDs.
TEST(ProcInfo, Self) {
  std::vector<pid_t> pids;
  ASSERT_EQ(list_pids(pids), SRESULT::Ok);
  EXPECT_NE(std::find(pids.begin(), pids.end(), getpid()), pids.end());
  std::string path;
  ASSERT_EQ(pid_path(getpid(), path), SRESULT::Ok);
  EXPECT_NE(path.find("ieso_macos_tests"), std::string::npos);
  TaskInfo ti;
  ASSERT_EQ(task_info(getpid(), ti), SRESULT::Ok);
  EXPECT_GT(ti.rss_bytes, 1u << 20);
  EXPECT_GE(ti.threads, 1u);
  std::uint32_t fds = 0;
  ASSERT_EQ(fd_count(getpid(), fds), SRESULT::Ok);
  EXPECT_GE(fds, 3u);
}

/// find_target matches by executable basename; unknown names are NotFound.
TEST(ProcInfo, FindTarget) {
  pid_t pid = 0;
  std::string exe;
  ASSERT_EQ(find_target("ieso_macos_tests", pid, exe), SRESULT::Ok);
  EXPECT_EQ(pid, getpid());
  EXPECT_EQ(find_target("NoSuchApp-ieso", pid, exe), SRESULT::NotFound);
}

/// Host facts and disk space are readable.
TEST(ProcInfo, HostFacts) {
  std::string v;
  ASSERT_EQ(sysctl_string("kern.osproductversion", v), SRESULT::Ok);
  EXPECT_FALSE(v.empty());
  std::uint64_t free_bytes = 0;
  ASSERT_EQ(disk_free("/", free_bytes), SRESULT::Ok);
  EXPECT_GT(free_bytes, 0u);
  std::string id, ver;
  EXPECT_EQ(bundle_info("/usr/bin/true", id, ver), SRESULT::NotFound);
}
