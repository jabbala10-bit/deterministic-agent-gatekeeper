"""The known-bypass corpus: every trick the gate is supposed to refuse, with the exact outcome.

Two kinds of entry, and neither may ever reach ALLOW:

  * DENY entries are refused during canonicalisation or by a forbid, and carry the exact reason code;
  * REQUIRE_APPROVAL entries are attempts to look like an allowlisted resource. They are not
    malformed, so the gate treats them as what they are, an unknown destination that needs a human.

Add a row before you fix a bug, never after."""

from __future__ import annotations

REFUND = "payments.refund"
EMAIL = "email.send"
FETCH = "web.fetch"
REPORT = "db.report"

_OK_ACCOUNT = '"account_id":"acc-1001"'
_MAIL = '"subject":"Your statement","body":"Attached."'

# (name, tool, raw arguments, expected verdict, expected reason)
CORPUS: tuple[tuple[str, str, str, str, str], ...] = (
    # --- JSON representation: the gate and the tool must never read different values -------------
    ("json/float-amount", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":150.00,"currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:float_not_allowed"),
    ("json/exponent-amount", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":1e4,"currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:float_not_allowed"),
    ("json/nan-amount", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":NaN,"currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:non_finite_number"),
    ("json/duplicate-key", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"1.00","amount":"9000.00","currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:duplicate_key"),
    ("json/i64-max-integer", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":9223372036854775807,"currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:integer_out_of_range"),
    ("json/not-an-object", REFUND, '[1,2,3]', "DENY", "INVALID_ARGUMENTS:not_an_object"),
    ("json/truncated", REFUND, '{"account_id":', "DENY", "INVALID_ARGUMENTS:malformed_json"),
    ("json/trailing-comma", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"1.00","currency":"EUR"},}', "DENY", "INVALID_ARGUMENTS:malformed_json"),
    ("json/unknown-argument", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"1.00","currency":"EUR"},"memo":"x"}', "DENY", "INVALID_ARGUMENTS:unknown_argument"),
    ("json/missing-argument", REFUND, '{' + _OK_ACCOUNT + '}', "DENY", "INVALID_ARGUMENTS:missing_argument"),
    ("json/oversized-arguments", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"1.00","currency":"EUR"},"pad":"' + "x" * 65_600 + '"}', "DENY", "INVALID_ARGUMENTS:too_large"),
    ("json/lone-surrogate", EMAIL, '{"to":"alice@customer.example","subject":"s","body":"\\ud800"}', "DENY", "INVALID_ARGUMENTS:lone_surrogate"),
    ("json/cedar-uid-injection", REFUND, '{"account_id":"acc-1001\\" || true || \\"","amount":{"amount":"1.00","currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:account_id:bad_id"),

    # --- Money: exact minor units, or nothing ----------------------------------------------------
    ("money/number-not-string", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":15000,"currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:amount:amount_must_be_a_decimal_string"),
    ("money/scientific-notation", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"1e2","currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:amount:bad_amount"),
    ("money/sub-cent-precision", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"150.001","currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:amount:too_many_fraction_digits"),
    ("money/jpy-has-no-minor-units", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"150.00","currency":"JPY"}}', "DENY", "INVALID_ARGUMENTS:amount:too_many_fraction_digits"),
    ("money/negative", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"-5.00","currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:amount:bad_amount"),
    ("money/leading-zero", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"0150.00","currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:amount:bad_amount"),
    ("money/thousands-separator", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"1,500.00","currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:amount:bad_amount"),
    ("money/arabic-indic-digits", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"\\u0661\\u0665\\u0660","currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:amount:bad_amount"),
    ("money/whitespace-padded", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":" 150.00","currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:amount:bad_amount"),
    ("money/lowercase-currency", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"150.00","currency":"eur"}}', "DENY", "INVALID_ARGUMENTS:amount:bad_currency"),
    ("money/unknown-currency", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"150.00","currency":"XBT"}}', "DENY", "INVALID_ARGUMENTS:amount:unknown_currency"),
    ("money/currency-not-permitted", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"150.00","currency":"GBP"}}', "DENY", "INVALID_ARGUMENTS:amount:currency_not_allowed"),
    ("money/zero", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"0.00","currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:amount:out_of_bounds"),
    ("money/over-tool-maximum", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"1000000.01","currency":"EUR"}}', "DENY", "INVALID_ARGUMENTS:amount:out_of_bounds"),
    ("money/missing-currency", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"150.00"}}', "DENY", "INVALID_ARGUMENTS:amount:expected_amount_and_currency"),
    ("money/extra-field", REFUND, '{' + _OK_ACCOUNT + ',"amount":{"amount":"150.00","currency":"EUR","rate":"1.0"}}', "DENY", "INVALID_ARGUMENTS:amount:expected_amount_and_currency"),

    # --- URL host: every spelling of an address the resolver would accept ------------------------
    ("url/decimal-ip", FETCH, '{"url":"https://2130706433/latest/meta-data"}', "DENY", "INVALID_ARGUMENTS:url:ip_literal_not_allowed"),
    ("url/hex-ip", FETCH, '{"url":"https://0x7f.0.0.0x1/"}', "DENY", "INVALID_ARGUMENTS:url:ip_literal_not_allowed"),
    ("url/short-ip", FETCH, '{"url":"https://127.1/"}', "DENY", "INVALID_ARGUMENTS:url:ip_literal_not_allowed"),
    ("url/dotted-quad", FETCH, '{"url":"https://127.0.0.1/"}', "DENY", "INVALID_ARGUMENTS:url:ip_literal_not_allowed"),
    ("url/cloud-metadata-ip", FETCH, '{"url":"https://169.254.169.254/latest/meta-data"}', "DENY", "INVALID_ARGUMENTS:url:ip_literal_not_allowed"),
    ("url/ipv6-loopback", FETCH, '{"url":"https://[::1]/"}', "DENY", "INVALID_ARGUMENTS:url:ip_literal_not_allowed"),
    ("url/ipv4-mapped-ipv6", FETCH, '{"url":"https://[::ffff:127.0.0.1]/"}', "DENY", "INVALID_ARGUMENTS:url:ip_literal_not_allowed"),
    ("url/single-label-host", FETCH, '{"url":"https://localhost/"}', "DENY", "INVALID_ARGUMENTS:url:bad_host"),
    ("url/credentials-in-url", FETCH, '{"url":"https://bank.example@evil.test/"}', "DENY", "INVALID_ARGUMENTS:url:credentials_in_url"),
    ("url/empty-host", FETCH, '{"url":"https:///etc/passwd"}', "DENY", "INVALID_ARGUMENTS:url:empty_host"),
    ("url/underscore-host", FETCH, '{"url":"https://bank_example.test/"}', "DENY", "INVALID_ARGUMENTS:url:bad_host"),

    # --- URL syntax: characters and schemes parsers disagree about -------------------------------
    ("url/file-scheme", FETCH, '{"url":"file:///etc/passwd"}', "DENY", "INVALID_ARGUMENTS:url:scheme_not_allowed"),
    ("url/plaintext-scheme", FETCH, '{"url":"http://docs.bank.example/"}', "DENY", "INVALID_ARGUMENTS:url:scheme_not_allowed"),
    ("url/javascript-scheme", FETCH, '{"url":"javascript:alert(1)"}', "DENY", "INVALID_ARGUMENTS:url:malformed_url"),
    ("url/embedded-tab", FETCH, '{"url":"https://docs.bank.ex\\tample/"}', "DENY", "INVALID_ARGUMENTS:url:control_character"),
    ("url/embedded-newline", FETCH, '{"url":"https://docs.bank.example/\\npath"}', "DENY", "INVALID_ARGUMENTS:url:control_character"),
    ("url/backslash-separator", FETCH, '{"url":"https://docs.bank.example\\\\@evil.test/"}', "DENY", "INVALID_ARGUMENTS:url:illegal_character"),
    ("url/raw-space", FETCH, '{"url":"https://docs.bank.example/a b"}', "DENY", "INVALID_ARGUMENTS:url:illegal_character"),
    ("url/truncated-escape", FETCH, '{"url":"https://docs.bank.example/%2"}', "DENY", "INVALID_ARGUMENTS:url:invalid_percent_encoding"),
    ("url/bad-escape", FETCH, '{"url":"https://docs.bank.example/%zz"}', "DENY", "INVALID_ARGUMENTS:url:invalid_percent_encoding"),
    ("url/port-zero", FETCH, '{"url":"https://docs.bank.example:0/"}', "DENY", "INVALID_ARGUMENTS:url:bad_port"),
    ("url/port-overflow", FETCH, '{"url":"https://docs.bank.example:99999/"}', "DENY", "INVALID_ARGUMENTS:url:bad_port"),
    ("url/non-numeric-port", FETCH, '{"url":"https://docs.bank.example:443a/"}', "DENY", "INVALID_ARGUMENTS:url:bad_port"),
    ("url/not-a-url", FETCH, '{"url":"docs.bank.example/x"}', "DENY", "INVALID_ARGUMENTS:url:malformed_url"),

    # --- Looking like an allowlisted destination without being one -------------------------------
    ("lookalike/host-as-subdomain-of-attacker", FETCH, '{"url":"https://bank.example.attacker.test/"}', "REQUIRE_APPROVAL", "egress-approved"),
    ("lookalike/host-as-prefix", FETCH, '{"url":"https://bank.example.evil/"}', "REQUIRE_APPROVAL", "egress-approved"),
    ("lookalike/host-hyphen-splice", FETCH, '{"url":"https://bank-example.test/"}', "REQUIRE_APPROVAL", "egress-approved"),
    ("lookalike/allowlisted-host-in-path", FETCH, '{"url":"https://evil.test/bank.example/x"}', "REQUIRE_APPROVAL", "egress-approved"),
    ("lookalike/allowlisted-host-in-query", FETCH, '{"url":"https://evil.test/?next=https%3A%2F%2Fbank.example%2F"}', "REQUIRE_APPROVAL", "egress-approved"),
    ("lookalike/cyrillic-homoglyph-host", FETCH, '{"url":"https://b\\u0430nk.example/"}', "REQUIRE_APPROVAL", "egress-approved"),
    ("lookalike/recipient-domain-suffix-splice", EMAIL, '{"to":"a@customer.example.attacker.test",' + _MAIL + '}', "REQUIRE_APPROVAL", "egress-approved"),
    ("lookalike/cyrillic-homoglyph-recipient", EMAIL, '{"to":"a@cust\\u043emer.example",' + _MAIL + '}', "REQUIRE_APPROVAL", "egress-approved"),

    # --- Email addressing ------------------------------------------------------------------------
    ("email/two-at-signs", EMAIL, '{"to":"a@b@customer.example",' + _MAIL + '}', "DENY", "INVALID_ARGUMENTS:to:bad_address"),
    ("email/display-name", EMAIL, '{"to":"Alice <alice@customer.example>",' + _MAIL + '}', "DENY", "INVALID_ARGUMENTS:to:bad_address"),
    ("email/address-list", EMAIL, '{"to":"alice@customer.example,exfil@attacker.test",' + _MAIL + '}', "DENY", "INVALID_ARGUMENTS:to:bad_address"),
    ("email/quoted-local-part", EMAIL, '{"to":"\\"a@b\\"@customer.example",' + _MAIL + '}', "DENY", "INVALID_ARGUMENTS:to:bad_address"),
    ("email/non-ascii-local-part", EMAIL, '{"to":"al\\u00efce@customer.example",' + _MAIL + '}', "DENY", "INVALID_ARGUMENTS:to:bad_local_part"),
    ("email/ip-domain", EMAIL, '{"to":"a@127.0.0.1",' + _MAIL + '}', "DENY", "INVALID_ARGUMENTS:to:ip_literal_not_allowed"),
    ("email/single-label-domain", EMAIL, '{"to":"a@localhost",' + _MAIL + '}', "DENY", "INVALID_ARGUMENTS:to:bad_host"),

    # --- Text ------------------------------------------------------------------------------------
    ("text/bidi-override-subject", EMAIL, '{"to":"alice@customer.example","subject":"Invoice \\u202efdp.exe","body":"b"}', "DENY", "INVALID_ARGUMENTS:subject:bidi_control"),
    ("text/nul-byte-body", EMAIL, '{"to":"alice@customer.example","subject":"s","body":"a\\u0000b"}', "DENY", "INVALID_ARGUMENTS:body:control_character"),
    ("text/unassigned-code-point", EMAIL, '{"to":"alice@customer.example","subject":"s","body":"x\\u0378y"}', "DENY", "INVALID_ARGUMENTS:body:unassigned_code_point"),

    # --- Templates: no free-form command ever reaches a tool --------------------------------------
    ("template/unknown-name", REPORT, '{"report":{"name":"drop_tables","params":{}}}', "DENY", "INVALID_ARGUMENTS:report:unknown_template"),
    ("template/sql-in-name", REPORT, '{"report":{"name":"refund_summary; DROP TABLE t","params":{}}}', "DENY", "INVALID_ARGUMENTS:report:bad_template_name"),
    ("template/unknown-parameter", REPORT, '{"report":{"name":"customer_balance","params":{"customer_id":"c-1","limit":"1 OR 1=1"}}}', "DENY", "INVALID_ARGUMENTS:report:unknown_parameter"),
    ("template/missing-parameter", REPORT, '{"report":{"name":"refund_summary","params":{"account_id":"acc-1001"}}}', "DENY", "INVALID_ARGUMENTS:report:missing_parameter"),
    ("template/sql-in-parameter", REPORT, '{"report":{"name":"customer_balance","params":{"customer_id":"c-1\\u0027 OR 1=1--"}}}', "DENY", "INVALID_ARGUMENTS:report:customer_id:bad_id"),
    ("template/parameter-out-of-bounds", REPORT, '{"report":{"name":"refund_summary","params":{"account_id":"acc-1001","since_days":9999}}}', "DENY", "INVALID_ARGUMENTS:report:since_days:out_of_bounds"),
    ("template/params-not-an-object", REPORT, '{"report":{"name":"refund_summary","params":"account_id=acc-1001"}}', "DENY", "INVALID_ARGUMENTS:report:expected_params_object"),
    ("template/name-not-a-string", REPORT, '{"report":{"name":42,"params":{}}}', "DENY", "INVALID_ARGUMENTS:report:bad_template_name"),
    ("template/permitted-name-not-allowlisted", REPORT, '{"report":{"name":"pii_export","params":{"customer_id":"c-1"}}}', "DENY", "NO_MATCHING_PERMIT"),

    # --- Tool naming ------------------------------------------------------------------------------
    ("tool/case-variant", "Payments.Refund", '{}', "DENY", "UNKNOWN_TOOL"),
    ("tool/unregistered", "payments.transfer", '{}', "DENY", "UNKNOWN_TOOL"),
)
