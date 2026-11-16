# Azure Entra ID Backend Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** ProxySQL v4.0 connects to Azure Database for MySQL Flexible Server with a Microsoft Entra ID access token from an AKS workload identity, so that no MySQL password is stored for the application users or the monitor user.

**Architecture:** A new backend auth type `azure_entra` reuses the AWS IAM token machinery (session wait state, `SecureString`, pool isolation, kill helper, cleartext TLS handshake). Core gets a second token-source slot, so an Azure provider and an AWS provider can be installed at the same time. A new in-tree plugin `plugins/azure_entra/` gets the token from Entra ID with libcurl and installs it through a new plugin ABI 17 service. The monitor can use the same slot.

**Tech Stack:** C++17, MariaDB Connector/C (vendored), libcurl (vendored, exported by core), nlohmann JSON (`deps/json`), TAP unit tests (`test/tap/tests/unit/`).

**Spec:** GitHub issue sysown/proxysql#6649 (body = `/private/tmp/claude-502/-Users-o-mattsson-git-github-proxysql/8e7ae0fb-b261-4329-871b-58c2bac707c8/scratchpad/issue-azure-entra-backend-auth.md`). The maintainers have not answered the design questions yet ("on our radar"). This plan picks answers; each pick is marked **Decision** and can change after maintainer feedback.

**Branch:** `feature/azure-entra-backend-auth` (from `upstream/v3.0` at `663e84aa6`). Do not commit this plan file to the upstream PR.

## Global Constraints

- All new core code compiles only with `PROXYSQL40`. Stable and Innovative tiers do not change (invariant I-2, `doc/agents/invariants.md`).
- Build: `make cleanall` once, then `PROXYSQL40=1 make debug -j$(nproc)` on every build. Never compile one translation unit alone (`CLAUDE.md`).
- Policy JSON: `{"backend_auth":{"type":"azure_entra"}}`. Type name string: `azure_entra`.
- Fail closed: every malformed or unsupported `backend_auth` stays `INVALID` (issue #6413). Never fall back to sending a password.
- Token scope default: `https://ossrdbms-aad.database.windows.net/.default`.
- Allowed endpoint suffixes (case-insensitive, at least one label before the suffix): `mysql.database.azure.com`, `mysql.database.chinacloudapi.cn`, `mysql.database.usgovcloudapi.net`.
- Handshake: TLS enforced, server certificate verified, `MARIADB_OPT_TLS_SERVER_NAME` = configured endpoint, `mysql_clear_password`, no auto-reconnect. Same as AWS IAM at `lib/mysql_connection.cpp:1185-1209`.
- Token wait in session: 5 s (existing constant, `lib/MySQL_Session.cpp:10606`). The plugin HTTP timeout is 4 s, so the session gets a provider error, not a timeout.
- Token values never reach a log, an error message or a stats row. Log only category, Entra `error` code and `correlation_id`.
- Users without `backend_auth` keep the lock-free skip at `lib/MySQL_Backend_Auth.cpp:262`.
- Tests: unit tests in `test/tap/tests/unit/`, registered in `test/tap/tests/unit/Makefile` (`UNIT_TESTS +=`, near line 739) and in `test/tap/groups/groups.json` as `[ "unit-tests-g1","@proxysql_min_version:4.0" ]`.

## Decisions (open questions in #6649)

1. **Interface (Q2):** keep the `AwsIam*` types unchanged and reuse them for Entra. No rename. This keeps the diff small and the ABI-13 layout untouched. A later rename to provider-neutral names is a separate change.
2. **Slots (Q1, Q2):** one slot for each provider, selected by `enum class BackendTokenProvider : uint8_t { AWS_IAM = 0, AZURE_ENTRA = 1 }`.
3. **ABI:** layout 16 → 17. Append two services to the end of `ProxySQL_PluginServices`. Layouts 1-10, 13 and 16 stay loadable.
4. **Provider location (Q3):** `plugins/azure_entra/`, built by the top-level Makefile when `PROXYSQL40=1`, like `plugins/mysql_router`.
5. **Monitor (Q4):** in scope, Task 9. Without it, Entra-only mode is not usable.
6. **Token wait (Q5):** stays 5 s. The provider refreshes ahead of expiry, so only a cold cache waits for Entra.
7. **Endpoint suffix:** required (change from the issue text, which said "no host suffix rule"). Reason: one Entra token is valid for every Azure MySQL server in the tenant, so sending it to a non-Azure host leaks a tenant-wide credential. The AWS path has the same rule.

## Review Focus

- Pod start with a cold cache: the first connections wait for one HTTPS call. Expect success within 5 s, or a clear `provider_error` log line. Test: Task 7, `cold_cache_single_fetch`.
- Many sessions at once on a cold cache: expect one HTTP call, not one per session. Test: Task 7, `concurrent_requests_coalesce`.
- Projected service-account token file rotated by kubelet: expect the next exchange to read the new file content. Test: Task 6, `assertion_reread_each_exchange`.
- Endpoint in uppercase or with a `privatelink` label: expect accept. Test: Task 2, `uppercase_and_privatelink_accepted`.
- Token rejected by the server (1045) because the Entra user was dropped: expect one fresh-token retry, then a fail with `backend_auth_rejected`, no loop, and other users keep the cached token. Tests: Task 4b, `entra_1045_invalidates_once`; Task 7, `invalidate_rate_limited`.

---

### Task 0: Spike — Connector/C handshake against real Azure

This is the main unverified risk from the investigation. Do it before Task 1. Do not commit the spike.

**Files:**
- Create (scratch, outside the repo): `spike_entra_connect.cpp`

- [ ] **Step 1: Get a token**

Run: `az account get-access-token --resource-type oss-rdbms --query accessToken -o tsv > /tmp/entra.tok`
Expected: a JWT (3 dot-separated parts).

- [ ] **Step 2: Build a 40-line client against `deps/mariadb-client-library`** that sets `MYSQL_OPT_SSL_ENFORCE`, `MYSQL_OPT_SSL_VERIFY_SERVER_CERT`, `MYSQL_ENABLE_CLEARTEXT_PLUGIN`, `MARIADB_OPT_TLS_SERVER_NAME`, `MYSQL_OPT_SSL_CA` (DigiCert Global Root G2 + Microsoft RSA Root CA 2017 bundle), then `mysql_real_connect(host, entra_user, token, ...)` and `SELECT CURRENT_USER()`.

- [ ] **Step 3: Run against the Klaravik ACC Flexible Server with an Entra admin or a `CREATE AADUSER` user**

Expected: connect succeeds; `CURRENT_USER()` returns the Entra principal. Record the result in #6649 as a comment. If it fails, stop the plan and report the error.

---

### Task 1: Policy type `azure_entra`

**Files:**
- Modify: `include/MySQL_Backend_Auth.h:12-16` (enum), `lib/MySQL_Backend_Auth.cpp:163-174` (type name), `lib/MySQL_Backend_Auth.cpp:217-223` (parser)
- Test: `test/tap/tests/unit/azure_entra_policy_unit-t.cpp`

**Interfaces:**
- Produces: `MySQLBackendAuthType::AZURE_ENTRA` (appended after `INVALID`, so existing values do not change); `bool mysql_backend_auth_uses_token(MySQLBackendAuthType type)` → true for `AWS_IAM` and `AZURE_ENTRA`; `const char* backend_token_log_label(MySQLBackendAuthType type)` → `"AWS IAM"` or `"Azure Entra"`, for log and error text. AWS text stays exactly as today, so operator alerts and `aws_iam_session_state_unit-t.cpp:797` keep working.

- [ ] **Step 1: Write the failing test** (style of `aws_iam_policy_unit-t.cpp`)

```cpp
// azure_entra_policy_parses
auto p = parse_mysql_backend_auth_policy("app", R"({"backend_auth":{"type":"azure_entra"}})", true);
ok(p.type == MySQLBackendAuthType::AZURE_ENTRA && p.ignored_password, "azure_entra parsed, password ignored");
ok(strcmp(mysql_backend_auth_type_name(MySQLBackendAuthType::AZURE_ENTRA), "azure_entra") == 0, "type name");
// still fail closed
ok(parse_mysql_backend_auth_policy("app", R"({"backend_auth":{"type":"Azure_Entra"}})", false).type
   == MySQLBackendAuthType::INVALID, "case-sensitive: unknown type is INVALID");
ok(mysql_backend_auth_uses_token(MySQLBackendAuthType::AZURE_ENTRA) &&
   mysql_backend_auth_uses_token(MySQLBackendAuthType::AWS_IAM) &&
   !mysql_backend_auth_uses_token(MySQLBackendAuthType::PASSWORD) &&
   !mysql_backend_auth_uses_token(MySQLBackendAuthType::INVALID), "uses_token");
// a loaded row sets the fast-path flag
ok(add_backend_user("entra_app", "", R"({"backend_auth":{"type":"azure_entra"}})") &&
   GloMyAuth->has_non_password_backend_auth(), "flag set by azure_entra row");
```

- [ ] **Step 2: Register the test and run it**

Run: `PROXYSQL40=1 make build_tap_test_debug && test/tap/tests/unit/azure_entra_policy_unit-t`
Expected: FAIL, `AZURE_ENTRA` not declared.

- [ ] **Step 3: Implement.** Accept `"azure_entra"` next to `"aws_iam"` in the parser. Check that `MySQL_Authentication::add()` and `refresh_non_password_backend_auth_locked()` use `type != PASSWORD`, not `== AWS_IAM`; fix them if not. Change `lib/MySQL_Authentication.cpp:418` (`warn_for_iam_password`) to `mysql_backend_auth_uses_token(policy.type)` and print `backend_token_log_label()`, so an Entra row with a password gets the same warning. Test: `entra_row_with_password_warns` (capture stderr as `add_backend_user_capturing_stderr` does; expect `Azure Entra` in the log line, and the AWS case still prints its old text).

- [ ] **Step 4: Run the new test and `aws_iam_policy_unit-t`, `mysql_backend_auth_in_use_unit-t`, `mysql_users_rejected_attributes_unit-t`**

Expected: all PASS.

- [ ] **Step 5: Commit** `feat(backend-auth): add azure_entra policy type (#6649)`

---

### Task 2: Connection validation for Entra

**Files:**
- Modify: `include/MySQL_Backend_Auth.h:81-82`, `lib/MySQL_Backend_Auth.cpp` (after `validate_mysql_aws_iam_connection`)
- Test: `test/tap/tests/unit/azure_entra_connection_config_unit-t.cpp`

**Interfaces:**
- Consumes: `AwsIamConnectionConfigInput`, `AwsIamConnectionConfigResult`, `AwsIamConnectionConfigStatus` (unchanged).
- Produces:
  - `AwsIamConnectionConfigResult validate_mysql_azure_entra_connection(const AwsIamConnectionConfigInput&)` — ignores `region`; `result.key = { configured_endpoint, port, "", database_user }`.
  - `AwsIamConnectionConfigResult validate_mysql_backend_token_connection(MySQLBackendAuthType, const AwsIamConnectionConfigInput&)` — dispatches by type; any non-token type returns `INVALID_ENDPOINT` with code `"not_token_auth"`.

Check order (same as AWS): `support_compiled` → `port != 0` → endpoint suffix → `use_ssl` → CA.

- [ ] **Step 1: Write the failing tests**

| Test | Input change from a valid base (`app.mysql.database.azure.com`, 3306, TLS, CA set) | Expected status / code |
|---|---|---|
| `valid_public` | none | `OK`, key.region == "" |
| `valid_sovereign` | `x.mysql.database.chinacloudapi.cn`, `x.mysql.database.usgovcloudapi.net` | `OK` |
| `uppercase_and_privatelink_accepted` | `App.PrivateLink.MySQL.Database.Azure.com` | `OK` |
| `rds_endpoint_rejected` | `db.cluster-x.us-east-1.rds.amazonaws.com` | `INVALID_ENDPOINT` / `invalid_endpoint` |
| `ip_and_bare_suffix_rejected` | `10.0.0.5`, `mysql.database.azure.com`, `evil.mysql.database.azure.com.attacker.io`, trailing dot | `INVALID_ENDPOINT` |
| `unix_socket` | port 0 | `UNIX_SOCKET_NOT_ALLOWED` |
| `tls_required` | use_ssl false | `TLS_REQUIRED` |
| `ca_required` | ssl_ca and ssl_capath empty | `CA_TRUST_REQUIRED` |
| `region_ignored` | region "eu-west-1" | `OK`, key.region == "" |
| `dispatch` | `validate_mysql_backend_token_connection(AWS_IAM, rds input)` | same as `validate_mysql_aws_iam_connection` |

- [ ] **Step 2: Run** — Expected: FAIL, functions not declared.
- [ ] **Step 3: Implement.** Reuse `is_dns_label()`; lowercase the labels before the suffix compare. Apply the same rule to the AWS check so both token types treat case the same: lowercase the labels in `split_rds_endpoint()` (`lib/MySQL_Backend_Auth.cpp:39-79`) and compare the region without case (`:313`). Add `rds_uppercase_accepted` to `aws_iam_connection_config_unit-t.cpp`: `DB.cluster-x.us-east-1.RDS.amazonaws.com` with region `us-east-1` → `OK`.
- [ ] **Step 4: Run the new test and `aws_iam_connection_config_unit-t`** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(backend-auth): validate Azure Entra backend endpoints (#6649)`

---

### Task 3: One token-source slot for each provider

**Files:**
- Modify: `include/Aws_Iam_Types.h` (add enum), `include/Aws_Iam_Provider.h:166-206`, `lib/Aws_Iam_Provider.cpp:240-383`, `src/main.cpp:2070`
- Test: `test/tap/tests/unit/backend_token_slot_unit-t.cpp`

**Interfaces:**
- Produces (in `Aws_Iam_Types.h`): `enum class BackendTokenProvider : uint8_t { AWS_IAM = 0, AZURE_ENTRA = 1 };`
- Produces (in `Aws_Iam_Provider.h`):
  - `AwsIamTokenSourceLease acquire_backend_token_source(BackendTokenProvider)`
  - `bool install_global_backend_token_source(BackendTokenProvider, AwsIamTokenSource*, AwsIamTokenSourceDestroyFn, AwsIamModuleHandle)`
  - `bool uninstall_global_backend_token_source(BackendTokenProvider, AwsIamTokenSource* expected)`
  - `void shutdown_global_backend_token_sources()` — retires both slots; `main.cpp:2070` calls it.
- Produces (in `MySQL_Backend_Auth.h`): `bool backend_token_provider_for(MySQLBackendAuthType, BackendTokenProvider& out)` → false for non-token types.
- The existing `*_global_aws_iam_token_source` functions stay as wrappers for `AWS_IAM`. `GloAwsIamTokenSource` stays the AWS slot only. Prometheus AWS metrics stay on the AWS slot only.

Move the file-static slot state (`global_source_mutex`, `global_source_cv`, `installed_source`, `leased_global_source`, `global_source_accepting`, `global_source_leases`, retirement counters) into `struct TokenSourceSlot`, with `static TokenSourceSlot slots[2]`. `AwsIamTokenSourceLease` keeps a `TokenSourceSlot*` so `release()` decrements the right slot; make the new acquire function a friend.

- [ ] **Step 1: Write the failing tests** with two fake sources (copy the fake from `aws_iam_provider_boundary_unit-t.cpp`):
  - `slots_independent`: install fake A on `AWS_IAM`, fake B on `AZURE_ENTRA`; `acquire_backend_token_source(AZURE_ENTRA).get() == B`; `acquire_global_aws_iam_token_source().get() == A`.
  - `uninstall_one_keeps_other`: uninstall B; Azure acquire is empty; AWS acquire still returns A.
  - `lease_blocks_retire_of_own_slot_only`: hold an Azure lease; uninstall AWS on another thread returns at once; Azure uninstall waits until the lease is released.
  - `shutdown_retires_both`.
- [ ] **Step 2: Run** — Expected: FAIL, functions not declared.
- [ ] **Step 3: Implement** as above.
- [ ] **Step 4: Run the new test and every `aws_iam_*_unit-t`** — Expected: PASS, no change in the AWS tests.
- [ ] **Step 5: Commit** `refactor(backend-auth): one token-source slot per provider (#6649)`

---

### Rule for Tasks 4a and 4b: convert every `AWS_IAM` check

The code has 23 `MySQLBackendAuthType::AWS_IAM` literals outside `lib/MySQL_Backend_Auth.cpp`. Each one that falls through to a password branch sends the frontend password to Azure for an Entra connection. Convert all of them:

- A check that means "token handshake" → `mysql_backend_auth_uses_token(type)`.
- A literal `AWS_IAM` passed as an argument (for example into `KillArgs`) → the connection's own `backend_auth_type()`.
- Keep `AWS_IAM` only where the code needs an AWS region.
- Log and error lines: replace the literal "AWS IAM" with `backend_token_log_label(type)` (Task 1). AWS output does not change.

Acceptance check after Task 4b: `git grep -n 'MySQLBackendAuthType::AWS_IAM' -- lib src` lists only the parser and type name in `lib/MySQL_Backend_Auth.cpp`, the provider mapping (`backend_token_provider_for`) and the region-only lines. Paste the output in the Task 4b commit message.

### Task 4a: Connection, pool and kill path treat Entra as a token type

**Files:**
- Modify: `lib/mysql_connection.cpp:592-597` (`set_backend_auth_type`), `:1185` (handshake), `:1258` (assert), `:1513`; `lib/MySQL_HostGroups_Manager.cpp:3060`, `:3092-3103` (kill args); `lib/MySQL_Session.cpp:328` (`KillArgs` constructor drops the password), `:387` (`kill_query_thread` token mode), `:430-455` (kill helper: slot and validator by type), `:2839-2862` (KILL QUERY on timeout)
- Test: extend `test/tap/tests/unit/aws_iam_pool_unit-t.cpp` and `test/tap/tests/unit/aws_iam_kill_helper_unit-t.cpp` (new cases at the end)

**Interfaces:**
- Consumes: `mysql_backend_auth_uses_token()`, `backend_token_log_label()` (Task 1); `validate_mysql_backend_token_connection()` (Task 2); `backend_token_provider_for()`, `acquire_backend_token_source()` (Task 3).
- Follow the rule above. The handshake error text becomes `"%s backend authentication requires a TCP endpoint and handshake token"` with `backend_token_log_label(type)`. The assert at `mysql_connection.cpp:1258` becomes `assert(!mysql_backend_auth_uses_token(backend_auth_type_))`.

- [ ] **Step 1: Write the failing tests:**
  - `entra_conn_not_reset_queued`: a healthy `AZURE_ENTRA` connection returned to the pool is destroyed, not queued for `COM_CHANGE_USER` reset.
  - `entra_conn_keeps_identity`: `set_backend_auth_type(AZURE_ENTRA)` after `attach_aws_iam_token` keeps the token (it is cleared only for non-token types).
  - `entra_kill_args_type`: the kill args for an Entra connection (pool path and KILL QUERY path) carry `AZURE_ENTRA`.
  - `entra_kill_args_no_password`: `KillArgs` built with `AZURE_ENTRA` and a non-null password has `password == nullptr`.
  - `entra_kill_thread_uses_token`: `kill_query_thread` with `AZURE_ENTRA` args takes the token path (fake Azure source receives `request_blocking()`), never the password path.
- [ ] **Step 2: Run** — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `aws_iam_pool_unit-t`, `aws_iam_connection_secret_unit-t`, `aws_iam_kill_helper_unit-t`** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(backend-auth): token handshake, pool and kill rules for azure_entra (#6649)`

---

### Task 4b: Session routes Entra to the Azure slot

**Files:**
- Modify `lib/MySQL_Session.cpp` at:
  - `:86-89` (record helper)
  - `:4155-4170` (connect timeout log and count)
  - `:4266-4276` (retry state reset before connect)
  - `:4300-4311` (retry state reset on success)
  - `:4418-4440` (1045 invalidation)
  - `:4664-4670` (change user: destroy and reconnect)
  - `:10273` (`force_fresh_iam_connection`)
  - `:10444`, `:10458` (`last_pool_ff`)
  - `:10565-10633` (connect path)
  - `:11135` (`create_new_session_and_reset_connection`: destroy, never reset)
- Modify `include/MySQL_Session.h:269-274` if `fail_aws_iam_backend` needs the type.
- Test: extend `test/tap/tests/unit/aws_iam_session_state_unit-t.cpp`

**Interfaces:**
- Consumes: `backend_token_provider_for()`, `acquire_backend_token_source()` (Task 3), `validate_mysql_backend_token_connection()` (Task 2).
- `static void record_backend_token_connection(MySQLBackendAuthType, bool success)` replaces `record_aws_iam_backend_connection`.
- Connect path: `if (mysql_backend_auth_uses_token(backend_auth_policy.type))`; lease and validator chosen by type; the rest of the wait state stays as is.
- 1045 path: require `!failed_key.region.empty()` only for `AWS_IAM`; acquire the slot of `myconn->backend_auth_type()`.
- Follow the rule above Task 4a for every other line.

- [ ] **Step 1: Write the failing tests** (fake sources on both slots):
  - `entra_session_uses_azure_slot`: a session whose user has `azure_entra` parks in `WAITING_AWS_IAM_TOKEN`, and only the Azure fake receives `request()`; the AWS fake receives nothing.
  - `entra_no_source_fails_closed`: no Azure source installed → session fails with `token_source_unavailable`; no connect attempt with a password.
  - `entra_1045_invalidates_once`: a 1045 on an Entra connect calls `invalidate()` on the Azure fake once with the failed generation, retries once, then fails with `backend_auth_rejected`.
  - `entra_retry_flag_reset_on_success`: after a retry that succeeds, a later 1045 in the same session gets its own retry.
  - `entra_change_user_destroys`: a pooled `PASSWORD` connection handed to a session whose user is `azure_entra` is destroyed and reconnected; `async_change_user` is never called.
  - `entra_reset_destroys`: `create_new_session_and_reset_connection()` on an Entra connection destroys it; no `COM_CHANGE_USER` is sent.
  - `aws_unchanged`: an `aws_iam` session still uses the AWS slot.
- [ ] **Step 2: Run** — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run all `aws_iam_*_unit-t` and the new cases, then the acceptance check from the rule above** — Expected: PASS; the grep lists only the allowed lines.
- [ ] **Step 5: Commit** `feat(backend-auth): route azure_entra sessions to the Entra token source (#6649)`

---

### Task 5: Plugin ABI 17 — Entra token-source services

**Files:**
- Modify: `include/ProxySQL_Plugin.h` (ABI history comment after line 89, layout version constants near line 160, callbacks near line 427-431, struct tail before line 579), `lib/ProxySQL_PluginManager.cpp:404-418`, `:736-740`, version acceptance check; `doc/PLUGIN_API.md:388-414`; `test/tap/test_helpers/plugin_services_abi_layout.h`
- Test: `test/tap/tests/unit/plugin_abi17_entra_services_unit-t.cpp`

**Interfaces:**
- Produces: `ProxySQL_PluginServices::install_azure_entra_token_source` (type `proxysql_plugin_install_aws_iam_token_source_cb`) and `::uninstall_azure_entra_token_source` (type `proxysql_plugin_uninstall_aws_iam_token_source_cb`), appended last. They call `install/uninstall_global_backend_token_source(AZURE_ENTRA, ...)`.
- `PROXYSQL_PLUGIN_ABI_LAYOUT_VERSION` = 17, `_MAX` = 17.

- [ ] **Step 1: Write the failing test:** the services struct from the plugin manager installs a fake source into the Azure slot (`acquire_backend_token_source(AZURE_ENTRA)` returns it) and leaves the AWS slot empty; add `static_assert`s in the layout header that every ABI-16 offset is unchanged and the two new fields follow the last ABI-16 field.
- [ ] **Step 2: Run** — Expected: FAIL.
- [ ] **Step 3: Implement.** Accept ABI 17 and keep accepting 1-10, 13 and 16 as today.
- [ ] **Step 4: Run the new test and the existing ABI-13 fixture tests (`fake_plugin_abi13`)** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(plugin-abi): ABI 17 adds Azure Entra token-source services (#6649)`

---

### Task 6: Plugin — configuration and token exchange (pure logic)

**Files:**
- Create: `plugins/azure_entra/Makefile`, `plugins/azure_entra/exports.map` (copy from `plugins/mysql_router`), `plugins/azure_entra/include/entra_config.h`, `plugins/azure_entra/src/entra_config.cpp`, `plugins/azure_entra/include/entra_exchange.h`, `plugins/azure_entra/src/entra_exchange.cpp`
- Modify: top-level `Makefile` — every place that names `mysql_router` gets the same line for `azure_entra`: build `:422-432`, clean `:538-561`, `:576`, `:590`, install `:609-611`, uninstall `:657`. Check with `grep -c mysql_router Makefile` = `grep -c azure_entra Makefile`.
- Test: `test/tap/tests/unit/azure_entra_plugin_unit-t.cpp` (compile plugin sources in, as `test/tap/tests/unit/Makefile:985` does for `mysql_router`)

**Interfaces:**
- Only AKS workload identity. IMDS is out of scope (see the end of the plan).
- `struct EntraConfig { std::string tenant_id, client_id, federated_token_file, authority_host, scope; };`
- `bool load_entra_config(const std::function<const char*(const char*)>& getenv_fn, EntraConfig& out, std::string& error)`
  - Env: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_FEDERATED_TOKEN_FILE` (all required), `AZURE_AUTHORITY_HOST` (default `https://login.microsoftonline.com/`), `PROXYSQL_AZURE_ENTRA_SCOPE` (default in Global Constraints).
  - `tenant_id` and `client_id` must be GUIDs (`^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$`), because they go into the URL and the form.
  - `authority_host` must start with `https://`.
- `struct HttpResponse { long status; std::string body; };`
- `using HttpPostFn = std::function<HttpResponse(const std::string& url, const std::string& form_body, std::chrono::milliseconds timeout)>;`
- `struct EntraTokenResponse { bool ok; SecureString access_token; std::chrono::seconds expires_in; AwsIamRedactedFailure failure; };`
- `EntraTokenResponse exchange_workload_identity(const EntraConfig&, const std::function<bool(std::string&)>& read_assertion, const HttpPostFn&)` — POST `{authority_host}{tenant_id}/oauth2/v2.0/token`, form: `client_id`, `scope`, `grant_type=client_credentials`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, `client_assertion` (URL-encoded).
- On failure: `failure.category` = `credential_provider_error` (cannot read assertion), `provider_error` (HTTP not 200 or bad JSON); `aws_error_code` = Entra `error`; `request_id` = `correlation_id`.

- [ ] **Step 1: Write the failing tests:**
  - `config_defaults`, `config_missing_tenant_fails`, `config_missing_token_file_fails`, `config_http_authority_rejected`.
  - `config_non_guid_rejected`: `AZURE_TENANT_ID="abc/../x"` and `AZURE_CLIENT_ID="a&scope=x"` each fail with an error that names the variable.
  - `exchange_builds_form`: the fake POST receives the exact URL and a form body with the 5 fields above, `client_assertion` URL-encoded.
  - `exchange_parses_success`: body `{"access_token":"tok","expires_in":3599}` → ok, token "tok", 3599 s.
  - `exchange_parses_error`: status 400, body `{"error":"invalid_client","correlation_id":"abc"}` → not ok, `aws_error_code=="invalid_client"`, `request_id=="abc"`, and the failure strings do not contain the assertion.
  - `assertion_reread_each_exchange`: two exchanges with a reader that returns "a1" then "a2" → the second POST contains "a2".
- [ ] **Step 2: Run** — Expected: FAIL.
- [ ] **Step 3: Implement.** JSON with `deps/json`. No libcurl in these files.
- [ ] **Step 4: Run** — Expected: PASS. Also `PROXYSQL40=1 make debug` builds `plugins/azure_entra/proxysql_azure_entra.so`.
- [ ] **Step 5: Commit** `feat(azure-entra): plugin config and token exchange (#6649)`

---

### Task 7: Plugin — token source, transport and install

**Files:**
- Create: `plugins/azure_entra/include/entra_token_source.h`, `plugins/azure_entra/src/entra_token_source.cpp`, `plugins/azure_entra/src/curl_transport.cpp`, `plugins/azure_entra/src/plugin.cpp`
- Test: add cases to `test/tap/tests/unit/azure_entra_plugin_unit-t.cpp`

**Interfaces:**
- `class AzureEntraTokenSource final : public AwsIamTokenSource` with constructor `AzureEntraTokenSource(EntraConfig, HttpPostFn, AwsIamRuntimeConfig, std::function<std::chrono::steady_clock::time_point()> now)`.
  - One cached token for the configured scope, used for every key (the token is not bound to a server or a user).
  - Cache rule: a token is usable until 30 s before it expires.
  - `request()`: usable token → post the completion at once; else queue the waiter and start at most one fetch. Respect `max_total_waiters` (→ `WAITER_LIMIT`).
  - Failure backoff: after a failed fetch, answer new requests with `PROVIDER_ERROR` (same redacted failure) for 2 s, then allow one new fetch. A usable cached token is still served during the backoff.
  - Background thread refreshes when less than 10 min is left, or at half the lifetime if the lifetime is under 20 min. A failed background refresh keeps the old token.
  - `invalidate(key, generation)`: drop the cached token only if `generation` matches **and** the last accepted invalidate was 60 s ago or more. Reason: one Entra user that the server rejects (missing `CREATE AADUSER`, wrong monitor user) must not empty the shared cache for every user on each attempt.
  - `request_blocking()`: same cache and rules, waits until `deadline`.
  - Destructor stops the thread and answers queued waiters with `SHUTDOWN`.
- `curl_transport.cpp`: `HttpPostFn make_curl_post()` — libcurl easy handle, `CURLOPT_TIMEOUT_MS` = 4000, TLS verification on, no redirects, response body capped at 64 KiB. Link as `plugins/genai/Makefile:124-125` does (curl stays unresolved, core owns it).
- `plugin.cpp`: descriptor `proxysql_plugin_descriptor_v1`, ABI 17. Init: `load_entra_config(getenv)`; on error log it and fail init. Create the source and call `services->install_azure_entra_token_source(source, destroy, module_handle)` as described in `doc/PLUGIN_API.md:388-414`. Call `uninstall_azure_entra_token_source` only to roll back a failed init (`include/ProxySQL_Plugin.h:545`); the service refuses calls outside init (`lib/ProxySQL_PluginManager.cpp:413-419`). Stop does not uninstall: `shutdown_global_backend_token_sources()` (Task 3) retires the source at process exit.

- [ ] **Step 1: Write the failing tests** (fake HTTP functions, fake clock):
  - `cold_cache_single_fetch`: one `request()` → one POST → one completion with status `OK`, `generation` 1.
  - `concurrent_requests_coalesce`: 50 `request()` calls before the fake POST returns → exactly 1 POST, 50 completions.
  - `cache_hit_no_fetch`: second request within lifetime → 0 extra POSTs, `token_cache_hits` == 1 in `snapshot()`.
  - `refresh_ahead`: advance the fake clock to 51 min of a 60 min token → a background POST runs before any request.
  - `invalidate_matching_generation_only`: `invalidate(key, 2)` with cached generation 1 keeps the token; `invalidate(key, 1)` drops it.
  - `invalidate_rate_limited`: `invalidate(key, 1)` drops the token, the next fetch gives generation 2, `invalidate(key, 2)` 10 s later keeps it, `invalidate(key, 2)` 61 s later drops it. Exactly 2 POSTs before the last invalidate.
  - `failure_backoff`: the fake POST returns 503; 20 requests within 2 s → 1 POST, 20 completions with `PROVIDER_ERROR`; a request at 2.1 s → a second POST.
  - `serve_until_expiry`: background refresh fails; a request with 60 s of token life left gets `OK` with the old token; with 20 s left it waits for a fetch.
  - `waiter_limit`: `max_total_waiters` = 2, 3 requests on a cold cache → third gets `WAITER_LIMIT`.
  - `shutdown_answers_waiters`: destroy with a pending waiter → completion `SHUTDOWN`.
- [ ] **Step 2: Run** — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS. Run with `WITHASAN=1 NOJEMALLOC=1` once as well.
- [ ] **Step 5: Commit** `feat(azure-entra): token source with cache and refresh (#6649)`

---

### Task 8: End-to-end backend connect with a fake Entra server

**Files:**
- Create: `test/tap/tests/test_azure_entra_backend_auth-t.cpp` and `test/tap/tests/test_azure_entra_backend_auth-t.env` (mirror `test_aws_iam_backend_auth-t.cpp` and its `.env`)
- Modify: `test/tap/groups/groups.json`, test Makefile entries next to `test_aws_iam_backend_auth-t`

**Interfaces:**
- Consumes: `test/deps/aws_iam_mysql_server` (TLS server that checks the cleartext password), a fake source installed with `install_global_backend_token_source(AZURE_ENTRA, ...)`, `GloMyMon->dns_cache->pin(kEndpoint, "127.0.0.1")`.
- `kEndpoint = "app-test.mysql.database.azure.com"`; the leaf certificate is issued for `kEndpoint`.

- [ ] **Step 1: Write the tests:**
  - `entra_connect_ok`: server expects token "entra-token" → backend connect succeeds; server saw `mysql_clear_password` over TLS with SNI `kEndpoint`.
  - `entra_untrusted_ca_fails`: leaf from an untrusted CA → connect fails; the token was never sent.
  - `entra_wrong_token_1045`: server rejects → one invalidate, one retry, then fail.
  - `aws_and_entra_side_by_side`: one AWS user and one Entra user in the same process both connect.
- [ ] **Step 2: Run** with `TEST_PY_TAP_INCL="test_azure_entra_backend_auth-t"` in the group that holds `test_aws_iam_backend_auth-t`.
Expected: PASS after Tasks 1-5.
- [ ] **Step 3: Commit** `test(backend-auth): azure_entra end-to-end with fake server (#6649)`

---

### Task 9: Monitor uses the Entra token

**Files:**
- Modify: `include/MySQL_Thread.h:686` area (variable), `lib/MySQL_Thread.cpp` (register `monitor_backend_auth` like `monitor_username`, under `PROXYSQL40`), `include/proxysql_structs.h:1507,1868` (thread-local), `lib/MySQL_Monitor.cpp:1670-1720`
- Create: `include/MySQL_Monitor_Token_Auth.h`, `lib/MySQL_Monitor_Token_Auth.cpp` (helper, so it can be unit tested)
- Test: `test/tap/tests/unit/monitor_entra_auth_unit-t.cpp`

**Interfaces:**
- Variable `mysql-monitor_backend_auth`: `password` (default) | `azure_entra`. Any other value is rejected by `SET`.
- `struct MonitorTokenAuth { SecureString token; AwsIamTokenKey key; uint64_t generation; std::string failure_code; };`
- `bool prepare_monitor_token_auth(MYSQL* mysql, const char* hostname, uint16_t port, bool use_ssl, const MySQLServers_SslParams* ssl, const char* monitor_user, std::chrono::steady_clock::time_point deadline, MonitorTokenAuth& out)` — validates with `validate_mysql_azure_entra_connection`, gets the token with `request_blocking()` from the Azure slot, and sets the same `mysql_options` as the backend handshake.
- `create_new_connection()`: when the variable is `azure_entra`, call the helper, pass `out.token.c_str()` as the password, clear the token after `mysql_real_connect`; on 1045 call `invalidate(out.key, out.generation)`. When the helper fails, set `mysql_error_msg` to `"azure_entra: <failure_code>"` and do not connect.
- Deadline: `now + mysql-monitor_connect_timeout`.

- [ ] **Step 1: Write the failing tests:**
  - `monitor_variable_rejects_unknown`: `SET mysql-monitor_backend_auth='foo'` fails; `'azure_entra'` and `'password'` succeed.
  - `monitor_helper_gets_token`: fake Azure source → `out.token == "entra-token"`, key has `monitor_user`.
  - `monitor_helper_unix_socket_fails`: port 0 → false, `failure_code == "unix_socket_not_allowed"`.
  - `monitor_helper_no_source_fails`: no source → false, `"token_source_unavailable"`; no password is sent.
- [ ] **Step 2: Run** — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS. Run `test_aws_iam_metrics-t` and one monitor TAP group to check that the default `password` path does not change.
- [ ] **Step 5: Commit** `feat(monitor): Entra token auth for the MySQL monitor (#6649)`

---

### Task 10: Documentation and live verification

**Files:**
- Modify: `doc/PLUGIN_API.md` (ABI 17 section), create `doc/azure_entra_backend_auth.md` (operator guide: Entra setup with `CREATE AADUSER`, AKS workload identity env, `mysql_users` row, `mysql-monitor_backend_auth`, CA bundle, failure codes)

- [ ] **Step 1: Write the operator guide.** Include an example `mysql_users` row with an empty password and the policy attribute, and the `plugins = (azure_entra)` line for `proxysql.cnf`.
- [ ] **Step 2: Live test on Klaravik ACC (AKS + Flexible Server, `aad_auth_only = OFF` first):** deploy the PR image, connect an app user and the monitor with Entra; then set `aad_auth_only = ON` and repeat.
Expected: queries succeed; `stats_mysql_global` `Aws_Iam_*` rows show no Entra traffic (Entra stats are out of scope, see below); monitor `read_only` checks return data.
- [ ] **Step 3: Commit** `docs(backend-auth): Azure Entra operator guide (#6649)`

## Out of scope (follow-up issues)

- IMDS (Instance Metadata Service) as a token source. Klaravik uses AKS workload identity. When IMDS is added, set `CURLOPT_NOPROXY` for `169.254.169.254` and select it only by explicit config, never as a fallback.
- `stats_mysql_global` and Prometheus rows for the Entra slot (logs carry the failures in this plan).
- Monitor token auth for AWS IAM.
- Renaming `AwsIam*` types to provider-neutral names.
- A variable for the 5 s token wait.
