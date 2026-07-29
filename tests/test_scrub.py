#!/usr/bin/env python3
"""Tests for scripts/scrub.py.

Run: python3 -m unittest discover -s tests -v

The redaction cases below are the contract: each "must redact" case is a leak
class that reached a cleaned session before the contextual-entropy pass
existed, and each "must not redact" case is a structural identifier that an
ungated entropy scan would destroy. Both directions matter -- a scrubber that
redacts message ids and content hashes is unusable, which is why cue-gating
and the identifier allowlist are load-bearing rather than incidental.
"""

import importlib.util
import json
import os
import unittest

_SCRUB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "scrub.py"
)
_spec = importlib.util.spec_from_file_location("scrub", _SCRUB_PATH)
scrub = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scrub)

REDACTED = "[REDACTED_SECRET]"


def clean(text):
    """Scrub a string embedded in a JSON session line, return the cleaned output."""
    out, _report = scrub.scrub_text(json.dumps({"text": text}), "test")
    return out


class TestContextualEntropy(unittest.TestCase):
    """Cue-gated entropy: unknown-provider and ad hoc token shapes."""

    def assert_redacted(self, text, secret):
        out = clean(text)
        self.assertNotIn(secret, out, f"secret survived scrubbing: {text!r}")
        self.assertIn(REDACTED, out)

    def assert_preserved(self, text, token):
        out = clean(text)
        self.assertIn(token, out, f"structural identifier was redacted: {text!r}")

    def test_nonstandard_prefix_key_in_env_assignment(self):
        secret = "ck_5EU7MvoUauUFQIFnS9YZlongenough123"
        self.assert_redacted(f'export COMPOSIO_KEY="{secret}"', secret)

    def test_nonstandard_prefix_key_after_cue_word(self):
        secret = "ck_5EU7MvoUauUFQIFnS9YZlongenough123"
        self.assert_redacted(f"the api_key: {secret} was rotated", secret)

    def test_bearer_token_with_base64_plus_and_slash(self):
        secret = "aB3+dE9/fGh1JkL2mNo4PqR6sTu8VwX0yZ12ab=="
        self.assert_redacted(f"Authorization: Bearer {secret}", secret)

    def test_unspaced_assignment_swallows_cue(self):
        # api_key=<secret> is one token under the candidate class, so the cue
        # never reaches the preceding window; the embedded-cue re-anchor covers it.
        secret = "Zq7Z1xT9pL2mNb8vCx4wEr6tYu0iOp3aSdFgHjKl"
        self.assert_redacted(f"api_key={secret}", secret)

    def test_password_colon_opaque_token(self):
        secret = "r4Nd0mLyGeneratedP4ssPhrase99xQ"
        self.assert_redacted(f"password: {secret}", secret)

    def test_uncued_high_entropy_is_left_alone(self):
        # No cue in the window: base64 content, not a credential.
        token = "aGVsbG8gd29ybGQgdGhpcyBpcyBmaW5l"
        self.assert_preserved(f"payload {token} content", token)

    def test_uuid_preserved(self):
        token = "550e8400-e29b-41d4-a716-446655440000"
        self.assert_preserved(f"request {token} completed", token)

    def test_git_sha_preserved(self):
        token = "9f2a1c4b8e6d3f0a7b5c2e9d1a8f4b6c3e0d7a2f"
        self.assert_preserved(f"commit {token} done", token)

    def test_structural_id_prefixes_preserved_when_uncued(self):
        # Uncued, the allowlist protects tool-call and message ids, which are
        # high-entropy by construction and appear constantly in transcripts.
        for token in ("msg_01ABCdefGHIjklMNOpqrsTUVwx", "toolu_01XYZabcDEFghiJKLmnoPQR"):
            with self.subTest(token=token):
                self.assert_preserved(f"replaying {token} now", token)

    def test_structural_id_prefixes_are_redacted_when_cued(self):
        # Deliberately fail-closed, and the inverse of the case above: an id
        # shape sitting behind an explicit secret cue is treated as a secret,
        # because a prefix is trivial for a real credential to wear. See
        # TestAllowlistCannotShieldCuedSecrets for the bypass this prevents.
        for token in ("msg_01ABCdefGHIjklMNOpqrsTUVwx", "toolu_01XYZabcDEFghiJKLmnoPQR"):
            with self.subTest(token=token):
                self.assertNotIn(token, clean(f"token: {token}"))

    def test_sha256_content_hash_preserved(self):
        token = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assert_preserved(f"sha256: {token}", token)

    def test_low_entropy_cued_token_preserved(self):
        # Repetitive strings clear the length bar but not the entropy bar.
        token = "aaaaaaaaaaaaaaaaaaaaaaaa"
        self.assert_preserved(f"token: {token}", token)


class TestCueInSiblingKey(unittest.TestCase):
    """The cue lives in the JSON key; the value is scrubbed as its own string.

    This is the shape secrets actually take in agent transcripts -- tool-call
    arguments and API payloads -- so a cue gate that only looks inside one
    string misses the common case entirely.
    """

    SECRET = "Zq7Z1xT9pL2mNb8vCx4wEr6tYu0iOp3aSdFgHjKl"

    def assert_secret_gone(self, raw):
        cleaned, _ = scrub.scrub_text(raw, "test")
        self.assertNotIn(self.SECRET, cleaned)

    def test_flat_secret_named_key(self):
        self.assert_secret_gone(json.dumps({"api_key": self.SECRET}))

    def test_camel_case_key(self):
        self.assert_secret_gone(json.dumps({"apiKey": self.SECRET}))

    def test_nested_tool_call_arguments(self):
        self.assert_secret_gone(
            json.dumps({"tool": "call_api", "arguments": {"apiKey": self.SECRET, "url": "https://x"}})
        )

    def test_password_and_authorization_keys(self):
        for key in ("password", "authorization", "client_secret", "access_token"):
            with self.subTest(key=key):
                self.assert_secret_gone(json.dumps({key: self.SECRET}))

    def test_ordinary_key_does_not_force_redaction(self):
        # A non-cue key must not turn arbitrary content into a redaction.
        raw = json.dumps({"description": "aGVsbG8gd29ybGQgdGhpcyBpcyBmaW5l"})
        cleaned, _ = scrub.scrub_text(raw, "test")
        self.assertIn("aGVsbG8gd29ybGQgdGhpcyBpcyBmaW5l", cleaned)


class TestAllowlistCannotShieldCuedSecrets(unittest.TestCase):
    """Once cued, the structural-identifier allowlist must not apply.

    A git SHA or message id never legitimately sits behind `api_key:`, while
    real secrets in exactly those shapes are common.
    """

    def assert_redacted(self, text, secret):
        self.assertNotIn(secret, clean(text))

    def test_allowlisted_prefix_does_not_shield_cued_secret(self):
        secret = "call_Zq7Z1xT9pL2mNb8vCx4wEr6tYu0iOp3aSdFgHjKl99"
        self.assert_redacted(f"api_key: {secret}", secret)

    def test_msg_prefixed_high_entropy_secret_when_cued(self):
        secret = "msg_ZQ7XPl9AktR2CvBnM4WsEo6TuY1FdGhKl0aQr3"
        self.assert_redacted(f"token: {secret}", secret)

    def test_40_char_hex_when_cued_is_redacted(self):
        secret = "3f9a2b71c4d8e6f10a5b9c2d7e4f8a1b6c3d9e0f"
        self.assert_redacted(f"api_key: {secret}", secret)

    def test_64_char_hex_when_cued_is_redacted(self):
        secret = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assert_redacted(f"client_secret: {secret}", secret)

    def test_same_shapes_survive_when_uncued(self):
        # The allowlist still protects structural ids in ordinary prose.
        for token in (
            "3f9a2b71c4d8e6f10a5b9c2d7e4f8a1b6c3d9e0f",
            "msg_01ABCdefGHIjklMNOpqrsTUVwx",
            "550e8400-e29b-41d4-a716-446655440000",
        ):
            with self.subTest(token=token):
                self.assertIn(token, clean(f"processing {token} now"))


class TestSplitAndDistantSecrets(unittest.TestCase):
    def test_verbose_field_name_still_cues(self):
        secret = "Zq7Z1xT9pL2mNb8vCx4wEr6tYu0iOp3aSdFgHjKl"
        text = f"very_long_descriptive_internal_service_authentication_secret_config_value_field = {secret}"
        self.assertNotIn(secret, clean(text))

    def test_unicode_split_secret_leaves_no_cleartext_tail(self):
        secret = "Zq7Z1xT9pL2mNb8vCx4wEr6tYu0iOp3aSdFgHjKl"
        tainted = secret[:20] + "–" + secret[20:]
        out = clean(f"api_key: {tainted}")
        self.assertNotIn(secret[:20], out)
        self.assertNotIn(secret[20:], out)

    def test_unicode_split_at_every_offset_leaks_nothing(self):
        # The split can land anywhere, including offsets that leave one side
        # below the length bar. Every fragment of 8+ chars must be gone.
        secret = "Zq7Z1xT9pL2mNb8vCx4wEr6tYu0iOp3aSdFgHjKl"
        for cut in range(1, len(secret)):
            tainted = secret[:cut] + "–" + secret[cut:]
            out = clean(f"api_key: {tainted}")
            for frag, label in ((secret[:cut], "head"), (secret[cut:], "tail")):
                if len(frag) >= 8:
                    with self.subTest(cut=cut, part=label):
                        self.assertNotIn(frag, out)


class TestBoundaries(unittest.TestCase):
    def test_token_at_min_len_is_redacted(self):
        secret = "aB3xK9pQ7zR2mN5v"  # exactly 16
        self.assertEqual(len(secret), scrub.ENTROPY_MIN_LEN)
        self.assertNotIn(secret, clean(f"api_key: {secret}"))

    def test_token_below_min_len_is_preserved(self):
        token = "aB3xK9pQ7zR2mN5"  # 15
        self.assertEqual(len(token), scrub.ENTROPY_MIN_LEN - 1)
        self.assertIn(token, clean(f"api_key: {token}"))

    def test_empty_and_whitespace_input(self):
        for raw in ("", "   ", "\n\n"):
            with self.subTest(raw=repr(raw)):
                cleaned, report = scrub.scrub_text(raw, "h")
                self.assertEqual(report["total_redactions"], 0)

    def test_long_line_with_cued_secret(self):
        secret = "Zq7Z1xT9pL2mNb8vCx4wEr6tYu0iOp3aSdFgHjKl"
        line = ("filler " * 20000) + f"api_key: {secret}"
        cleaned, _ = scrub.scrub_text(json.dumps({"t": line}), "h")
        self.assertNotIn(secret, cleaned)


class TestNamedPatterns(unittest.TestCase):
    """The pre-existing fixed-format detectors still fire."""

    def test_openai_key(self):
        secret = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
        self.assertNotIn(secret, clean(f"key {secret} here"))

    def test_aws_access_key(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        self.assertNotIn(secret, clean(f"aws {secret}"))

    def test_jwt(self):
        secret = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        self.assertNotIn(secret, clean(f"jwt {secret}"))

    def test_private_key_block(self):
        secret = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAxyz123\n"
            "-----END RSA PRIVATE KEY-----"
        )
        self.assertNotIn("MIIEowIBAAKCAQEAxyz123", clean(secret))


class TestNonSecretRedactions(unittest.TestCase):
    """Home paths, emails and private IPs are normalized, not flagged as secrets."""

    def test_home_path_username(self):
        out = clean("/Users/abhishek/projects/thing.py")
        self.assertNotIn("abhishek", out)
        self.assertIn("/Users/USER", out)

    def test_dash_encoded_home_path(self):
        out = clean("/-Users-abhishek-projects-thing")
        self.assertNotIn("abhishek", out)

    def test_email(self):
        out = clean("contact me at person@example.com please")
        self.assertNotIn("person@example.com", out)
        self.assertIn("[REDACTED_EMAIL]", out)

    def test_private_ip(self):
        out = clean("db at 10.1.2.3 is up")
        self.assertNotIn("10.1.2.3", out)
        self.assertIn("[REDACTED_IP]", out)

    def test_public_version_string_untouched(self):
        self.assertIn("1.2.3.4", clean("version 1.2.3.4 released"))


class TestStructureHandling(unittest.TestCase):
    """Scrubbing walks keys, nested values, and non-JSON lines."""

    def test_json_object_keys_are_scrubbed(self):
        raw = json.dumps({"/Users/abhishek/f.py": {"nested": "sk-abcdefghijklmnopqrstuvwxyz012345"}})
        cleaned, report = scrub.scrub_text(raw, "test")
        self.assertNotIn("abhishek", cleaned)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz012345", cleaned)
        self.assertGreater(report["total_redactions"], 0)

    def test_non_json_line_still_scrubbed(self):
        cleaned, _ = scrub.scrub_text("plain text with sk-abcdefghijklmnopqrstuvwxyz012345", "test")
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz012345", cleaned)

    def test_report_counts_reported(self):
        _cleaned, report = scrub.scrub_text(json.dumps({"t": "api_key: Zq7Z1xT9pL2mNb8vCx4wEr6tYu0iOp3aSdFgHjKl"}), "h")
        self.assertEqual(report["harness"], "h")
        self.assertIn("contextual_entropy", report["redactions"])

    def test_multiple_secrets_on_one_line_all_redacted(self):
        line = "first api_key: Zq7Z1xT9pL2mNb8vCx4wEr6tYu0iOp3aSdFgHjKl then password: Xy9KpLm2Qr7Tv4Nb8Wz1Cd6Fg"
        cleaned, _ = scrub.scrub_text(json.dumps({"t": line}), "test")
        self.assertNotIn("Zq7Z1xT9pL2mNb8vCx4wEr6tYu0iOp3aSdFgHjKl", cleaned)
        self.assertNotIn("Xy9KpLm2Qr7Tv4Nb8Wz1Cd6Fg", cleaned)


class TestEntropyHelpers(unittest.TestCase):
    def test_entropy_of_empty_string(self):
        self.assertEqual(scrub.token_shannon_entropy(""), 0.0)

    def test_entropy_ordering(self):
        low = scrub.token_shannon_entropy("aaaaaaaaaaaaaaaa")
        high = scrub.token_shannon_entropy("aB3xK9pQ7zR2mN5v")
        self.assertLess(low, high)

    def test_candidates_rejoin_non_ascii_split(self):
        # An en dash inside a token yields ONE candidate, not two fragments.
        got = list(scrub._candidates("api_key: abcd1234efgh–5678ijkl"))
        tokens = [t for _s, _e, t in got]
        self.assertIn("abcd1234efgh–5678ijkl", tokens)

    def test_candidates_do_not_rejoin_across_ascii_punctuation(self):
        # ';' separates real values; gluing there would chain redactions.
        tokens = [t for _s, _e, t in scrub._candidates("aaa;bbb")]
        self.assertEqual(tokens, ["aaa", "bbb"])

    def test_candidates_do_not_rejoin_across_whitespace(self):
        tokens = [t for _s, _e, t in scrub._candidates("aaa bbb")]
        self.assertEqual(tokens, ["aaa", "bbb"])


if __name__ == "__main__":
    unittest.main()


class TestNestedKeyCue(unittest.TestCase):
    """A secret-named key cues everything beneath it, not just a string value."""

    SECRET = "Zq7Z1xT9pL2mNb8vCx4wEr6tYu0iOp3aSdFgHjKl"

    def assert_gone(self, obj):
        cleaned, _ = scrub.scrub_text(json.dumps(obj), "test")
        self.assertNotIn(self.SECRET, cleaned)

    def test_list_under_secret_key(self):
        self.assert_gone({"api_keys": [self.SECRET]})

    def test_dict_under_secret_key(self):
        self.assert_gone({"secrets": {"prod": self.SECRET}})

    def test_deeply_nested(self):
        self.assert_gone({"credentials": {"a": {"b": [{"c": self.SECRET}]}}})


class TestCueVocabularyPrecision(unittest.TestCase):
    """Cue matching must not fire on ordinary coding-trace vocabulary."""

    def assert_preserved(self, obj, needle):
        cleaned, _ = scrub.scrub_text(json.dumps(obj), "test")
        self.assertIn(needle, cleaned)

    def test_tokenizer_name_survives(self):
        self.assert_preserved(
            {"tokenizer": "meta-llama/Llama-3.1-8B-Instruct"}, "meta-llama/Llama-3.1-8B-Instruct"
        )

    def test_secret_name_field_survives(self):
        self.assert_preserved({"secretName": "my-tls-certificate-secret"}, "my-tls-certificate-secret")

    def test_authorization_url_survives(self):
        self.assert_preserved(
            {"authorization_url": "https://accounts.google.com/o/oauth2/auth"}, "accounts.google.com"
        )

    def test_secretary_prose_survives(self):
        out = clean("secretary: aGVsbG8gd29ybGQgdGhpcyBpcyBmaW5l")
        self.assertIn("aGVsbG8gd29ybGQgdGhpcyBpcyBmaW5l", out)

    def test_compound_secret_field_still_cues(self):
        secret = "Zq7Z1xT9pL2mNb8vCx4wEr6tYu0iOp3aSdFgHjKl"
        text = f"service_authentication_secret_config_value_field = {secret}"
        self.assertNotIn(secret, clean(text))

    def test_added_vocabulary_cues(self):
        secret = "Zq7Z1xT9pL2mNb8vCx4wEr6tYu0iOp3aSdFgHjKl"
        for key in ("credentials", "passphrase", "pwd", "dsn", "cookie"):
            with self.subTest(key=key):
                cleaned, _ = scrub.scrub_text(json.dumps({key: secret}), "test")
                self.assertNotIn(secret, cleaned)
