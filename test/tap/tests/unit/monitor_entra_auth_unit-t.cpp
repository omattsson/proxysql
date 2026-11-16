/**
 * @file monitor_entra_auth_unit-t.cpp
 * @brief The MySQL monitor authenticates with an Azure Entra token (issue #6649).
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "Aws_Iam_Provider.h"
#include "MySQL_Monitor_Token_Auth.h"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

using Clock = std::chrono::steady_clock;

namespace {

constexpr const char *kEndpoint = "app.mysql.database.azure.com";

class FakeSource final : public AwsIamTokenSource {
public:
	AwsIamRequestHandle request(const AwsIamTokenKey&, uint64_t,
		std::weak_ptr<AwsIamCompletionSink>) override { return {}; }
	AwsIamTokenResult request_blocking(const AwsIamTokenKey& key, Clock::time_point) override {
		last_key = key;
		++calls;
		AwsIamTokenResult r;
		r.status = AwsIamStatus::OK;
		r.generation = 4;
		r.token = SecureString("ENTRA_MONITOR_TOKEN");
		return r;
	}
	void cancel(AwsIamRequestHandle) override {}
	void invalidate(const AwsIamTokenKey&, uint64_t) override {}
	void record_backend_connection(bool) override {}
	void record_waiting_session(bool) override {}
	AwsIamStatsSnapshot snapshot() const override { return {}; }
	AwsIamTokenKey last_key;
	int calls { 0 };
};

void test_variable() {
	ok(!GloMTH->set_variable((char *)"monitor_backend_auth", (char *)"foo"),
		"monitor_variable_rejects_unknown: 'foo' is refused");
	ok(GloMTH->set_variable((char *)"monitor_backend_auth", (char *)"azure_entra") &&
		GloMTH->set_variable((char *)"monitor_backend_auth", (char *)"password"),
		"monitor_backend_auth accepts 'azure_entra' and 'password'");
	char *value = GloMTH->get_variable_string((char *)"monitor_backend_auth");
	ok(value != nullptr && strcmp(value, "password") == 0, "the default and current value reads back");
	free(value);
}

void test_helper(FakeSource& source) {
	MYSQL *mysql = mysql_init(nullptr);
	MonitorTokenAuth out;
	const bool ready = prepare_monitor_token_auth(mysql, kEndpoint, 3306, true, nullptr, "monitor",
		Clock::now() + std::chrono::seconds(1), out);
	const AwsIamTokenKey expected { kEndpoint, 3306, "", "monitor" };
	ok(ready && std::string(out.token.c_str()) == "ENTRA_MONITOR_TOKEN" && out.generation == 4 &&
		out.key == expected && source.last_key == expected,
		"monitor_helper_gets_token: the monitor user gets a token from the Azure slot");
	mysql_close(mysql);

	mysql = mysql_init(nullptr);
	const int calls = source.calls;
	MonitorTokenAuth socket;
	ok(!prepare_monitor_token_auth(mysql, "/tmp/mysql.sock", 0, true, nullptr, "monitor",
		Clock::now() + std::chrono::seconds(1), socket) &&
		socket.failure_code == "unix_socket_not_allowed" && source.calls == calls,
		"monitor_helper_unix_socket_fails before any token request");
	mysql_close(mysql);
}

void test_no_source() {
	MYSQL *mysql = mysql_init(nullptr);
	MonitorTokenAuth out;
	ok(!prepare_monitor_token_auth(mysql, kEndpoint, 3306, true, nullptr, "monitor",
		Clock::now() + std::chrono::seconds(1), out) &&
		out.failure_code == "token_source_unavailable" && out.token.empty(),
		"monitor_helper_no_source_fails: no Azure source, no token, no password fallback");
	mysql_close(mysql);
}

} // namespace

int main() {
	plan(6);
	if (test_init_minimal() != 0 || test_init_query_processor() != 0 ||
		test_init_hostgroups() != 0) {
		BAIL_OUT("failed to initialize unit-test globals");
	}
	GloMTH->set_variable((char *)"ssl_p2s_ca", (char *)"/unit/fake-ca.pem");
	GloMTH->commit();
	mysql_thread___ssl_p2s_ca = strdup("/unit/fake-ca.pem");
	test_variable();
	{
		FakeSource source;
		publish_global_backend_token_source(BackendTokenProvider::AZURE_ENTRA, &source);
		test_helper(source);
		publish_global_backend_token_source(BackendTokenProvider::AZURE_ENTRA, nullptr);
	}
	test_no_source();
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}
