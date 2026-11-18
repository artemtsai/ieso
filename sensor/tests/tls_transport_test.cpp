/**
 * @file tls_transport_test.cpp
 * @brief Transport rule: TLS 1.3 + mTLS only, through libcurl. Real handshakes against local `openssl s_server`.
 */
#include <gtest/gtest.h>

#include <thread>

#include "cloud_client/cloud_client.hpp"
#include "ieso/macos/subprocess.hpp"
#include "test_util.hpp"

using namespace ieso;
using namespace ieso::macos;
using namespace ieso::test;
using namespace std::chrono_literals;

namespace {

/// @brief Throwaway PKI (via backend/certs/gen_certs.sh) plus helpers to run TLS servers.
class TlsLab : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_EQ(tmp_.path(dir_), SRESULT::Ok);
    ASSERT_EQ(make_pki(dir_ / "pki"), SRESULT::Ok);
    ASSERT_EQ(make_pki(dir_ / "other"), SRESULT::Ok);  // a second, untrusted CA
  }

  /// @brief Generates a PKI into @p out. @param[in] out Directory. @return Ok or IoError.
  SRESULT make_pki(const std::filesystem::path& out) {
    std::string log;
    int code = -1;
    HS_RETURN_IF_FAILED(Subprocess::Run({"/usr/bin/env", "IESO_CERT_OUT=" + out.string(), "/bin/bash",
                                         std::string(IESO_SOURCE_DIR) + "/backend/certs/gen_certs.sh", "ep-test"},
                                        60s, log, code));
    return code == 0 ? SRESULT::Ok : SRESULT::IoError;
  }

  /**
   * @brief Starts `openssl s_server` requiring a client certificate.
   * @param[in] port Port.
   * @param[in] version "-tls1_3" or "-tls1_2" (the only protocol the server accepts).
   * @param[out] out Server process.
   * @return SRESULT::Ok once it accepts connections.
   */
  SRESULT serve(int port, const std::string& version, std::unique_ptr<Subprocess>& out) {
    const auto pki = dir_ / "pki";
    HS_RETURN_IF_FAILED(Subprocess::Spawn({"/usr/bin/openssl", "s_server", "-accept", std::to_string(port), "-cert",
                                           (pki / "server.pem").string(), "-key", (pki / "server.key").string(),
                                           "-CAfile", (pki / "ca.pem").string(), "-Verify", "1", version, "-www"},
                                          out));
    std::string line;
    for (int i = 0; i < 50; ++i) {  // s_server prints "ACCEPT" when listening
      if (out->read_line(line, 100ms) == SRESULT::Ok && line.find("ACCEPT") != std::string::npos) return SRESULT::Ok;
    }
    return SRESULT::Timeout;
  }

  /// @brief TLS material for the native transport. @param[in] pki PKI dir. @param[in] with_id Load identity. @return Config.
  TlsConfig tls(const std::string& pki, bool with_id = true) const {
    TlsConfig t;
    t.ca_file = (dir_ / pki / "ca.pem").string();
    if (with_id) t.client_p12 = (dir_ / "pki" / "endpoint.p12").string();
    t.p12_password = "ieso";
    return t;
  }

  /// @brief GET https://localhost:<port>/ through @p t. @return HTTP status (0 = refused).
  static long get(ITransportClient& t, int port) {
    HttpResponse r;
    EXPECT_EQ(t.request("GET", "https://localhost:" + std::to_string(port) + "/", {}, "", r), SRESULT::Ok);
    return r.status;
  }

  TempDir tmp_;                 ///< Scratch.
  std::filesystem::path dir_;   ///< Scratch path.
};

}  // namespace

/// TLS 1.3 server + our CA + client identity: libcurl connects and reports TLSv1.3.
TEST_F(TlsLab, ConnectsWithTls13AndMtls) {
  std::unique_ptr<Subprocess> server;
  ASSERT_EQ(serve(18513, "-tls1_3", server), SRESULT::Ok);
  std::unique_ptr<CurlTransport> t;
  ASSERT_EQ(CurlTransport::Create(tls("pki"), t), SRESULT::Ok);
  HttpResponse r;
  ASSERT_EQ(t->request("GET", "https://localhost:18513/", {}, "", r), SRESULT::Ok);
  EXPECT_EQ(r.status, 200);
  EXPECT_EQ(r.tls_version, "TLSv1.3");
}

/// A server that only speaks TLS 1.2 is refused: no downgrade, no handshake.
TEST_F(TlsLab, RefusesTls12Server) {
  std::unique_ptr<Subprocess> server;
  ASSERT_EQ(serve(18512, "-tls1_2", server), SRESULT::Ok);
  std::unique_ptr<CurlTransport> t;
  ASSERT_EQ(CurlTransport::Create(tls("pki"), t), SRESULT::Ok);
  HttpResponse r;
  ASSERT_EQ(t->request("GET", "https://localhost:18512/", {}, "", r), SRESULT::Ok);
  EXPECT_EQ(r.status, 0);
  EXPECT_NE(r.tls_version, "TLSv1.2");
}

/// Pinned CA: a server certificate from another CA is refused even over TLS 1.3.
TEST_F(TlsLab, RefusesUnpinnedCa) {
  std::unique_ptr<Subprocess> server;
  ASSERT_EQ(serve(18514, "-tls1_3", server), SRESULT::Ok);
  std::unique_ptr<CurlTransport> t;
  ASSERT_EQ(CurlTransport::Create(tls("other"), t), SRESULT::Ok);
  EXPECT_EQ(get(*t, 18514), 0);
}

/// mTLS: without a client identity the server refuses the handshake; plain http:// is never attempted.
TEST_F(TlsLab, NeedsIdentityAndHttps) {
  std::unique_ptr<Subprocess> server;
  ASSERT_EQ(serve(18515, "-tls1_3", server), SRESULT::Ok);
  std::unique_ptr<CurlTransport> t;
  ASSERT_EQ(CurlTransport::Create(tls("pki", false), t), SRESULT::Ok);
  EXPECT_EQ(get(*t, 18515), 0);
  HttpResponse r;
  EXPECT_EQ(t->request("GET", "http://localhost:18515/", {}, "", r), SRESULT::InvalidArgument);
}
