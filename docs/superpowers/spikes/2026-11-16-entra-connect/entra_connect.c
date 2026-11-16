// Task 0 spike (#6649): same mysql_options as lib/mysql_connection.cpp:1199-1208.
#include <mysql.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
	if (argc != 5) { fprintf(stderr, "usage: host user token_file ca_file\n"); return 2; }
	static char token[16384];
	FILE *f = fopen(argv[3], "r");
	if (!f) { perror("token"); return 2; }
	size_t n = fread(token, 1, sizeof(token) - 1, f);
	fclose(f);
	while (n && (token[n - 1] == '\n' || token[n - 1] == '\r')) n--;
	token[n] = 0;

	MYSQL *m = mysql_init(NULL);
	my_bool on = 1, off = 0;
	mysql_options(m, MYSQL_OPT_SSL_ENFORCE, &on);
	mysql_options(m, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &on);
	mysql_options(m, MYSQL_ENABLE_CLEARTEXT_PLUGIN, &on);
	mysql_options(m, MYSQL_OPT_RECONNECT, &off);
	mysql_options(m, MYSQL_OPT_SSL_CA, argv[4]);
	mysql_options(m, MARIADB_OPT_TLS_SERVER_NAME, argv[1]);

	printf("connector %s\n", mysql_get_client_info());
	if (!mysql_real_connect(m, argv[1], argv[2], token, NULL, 3306, NULL, 0)) {
		printf("connect failed: %u %s\n", mysql_errno(m), mysql_error(m));
		memset(token, 0, sizeof(token));
		return 1;
	}
	memset(token, 0, sizeof(token));
	printf("cipher %s\n", mysql_get_ssl_cipher(m));
	if (mysql_query(m, "SELECT CURRENT_USER()") == 0) {
		MYSQL_RES *r = mysql_store_result(m);
		MYSQL_ROW row = mysql_fetch_row(r);
		printf("CURRENT_USER %s\n", row && row[0] ? row[0] : "(null)");
		mysql_free_result(r);
	}
	mysql_close(m);
	return 0;
}
