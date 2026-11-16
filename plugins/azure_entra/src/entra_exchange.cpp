#include "entra_exchange.h"

#include "../../../deps/json/json.hpp"

#include <cstdio>
#include <cstdlib>

namespace {

void cleanse(std::string& secret) {
	if (!secret.empty()) aws_iam_default_cleanse(&secret[0], secret.size());
}

// RFC 3986 unreserved characters stay; everything else is percent-encoded.
std::string form_encode(const std::string& value) {
	std::string out;
	out.reserve(value.size() * 3);
	for (const unsigned char c : value) {
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~') {
			out.push_back(static_cast<char>(c));
		} else {
			char hex[4];
			std::snprintf(hex, sizeof(hex), "%%%02X", c);
			out += hex;
		}
	}
	return out;
}

EntraTokenResponse failure(const char *category, const std::string& code = "",
	const std::string& correlation_id = "") {
	EntraTokenResponse r;
	r.failure.category = category;
	r.failure.aws_error_code = code;
	r.failure.request_id = correlation_id;
	return r;
}

std::string string_field(const nlohmann::json& body, const char *name) {
	const auto it = body.find(name);
	return it != body.end() && it->is_string() ? it->get<std::string>() : std::string();
}

} // namespace

EntraTokenResponse exchange_workload_identity(const EntraConfig& cfg,
	const std::function<bool(std::string&)>& read_assertion, const HttpPostFn& post) {
	std::string assertion;
	if (!read_assertion(assertion) || assertion.empty()) {
		return failure("credential_provider_error");
	}
	std::string form = "client_id=" + form_encode(cfg.client_id) +
		"&scope=" + form_encode(cfg.scope) +
		"&grant_type=client_credentials" +
		"&client_assertion_type=" + form_encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer") +
		"&client_assertion=" + form_encode(assertion);
	HttpResponse response = post(
		cfg.authority_host + cfg.tenant_id + "/oauth2/v2.0/token", form, kEntraHttpTimeout);
	cleanse(form);
	cleanse(assertion);

	const nlohmann::json body = nlohmann::json::parse(response.body, nullptr, false);
	cleanse(response.body);
	if (body.is_discarded() || !body.is_object()) {
		return failure("provider_error", response.status == 0 ? "transport" : "");
	}
	if (response.status != 200) {
		return failure("provider_error", string_field(body, "error"), string_field(body, "correlation_id"));
	}
	std::string token = string_field(body, "access_token");
	long long expires = 0;
	const auto exp = body.find("expires_in");
	if (exp != body.end() && exp->is_number_integer()) {
		expires = exp->get<long long>();
	} else if (exp != body.end() && exp->is_string()) {
		expires = std::atoll(exp->get<std::string>().c_str());
	}
	if (token.empty() || expires <= 0) {
		return failure("provider_error", "invalid_token_response");
	}
	EntraTokenResponse r;
	r.ok = true;
	r.access_token = SecureString(token);
	r.expires_in = std::chrono::seconds(expires);
	cleanse(token);
	return r;
}
