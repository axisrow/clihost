"""Table-driven parity tests for the Bash and Python env contracts (#113)."""
import os
import pathlib
import subprocess
import tempfile
import unittest

from ttydproxy.security import env_bool, env_int


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SHELL_CONTRACT = REPO_ROOT / "bin/env-contract.sh"


def bash_parse(function, name, value, *args):
    env = os.environ.copy()
    env.pop(name, None)
    if value is not None:
        env[name] = value
    command = (
        'source "$1"; shift; '
        f'{function} {name} "$@" && printf "%s" "${{{name}}}"'
    )
    return subprocess.run(
        ["bash", "-c", command, "bash", str(SHELL_CONTRACT), *map(str, args)],
        env=env,
        capture_output=True,
        text=True,
    )


class TestBooleanContractParity(unittest.TestCase):
    def test_same_boolean_inputs(self):
        cases = (
            (None, False, "false"),
            ("", True, "true"),
            ("  TRUE  ", False, "true"),
            ("1", False, "true"),
            ("yes", False, "true"),
            ("ON", False, "true"),
            ("0", True, "false"),
            ("No", True, "false"),
            ("off", True, "false"),
        )
        for value, default, expected in cases:
            with self.subTest(value=value, default=default):
                shell = bash_parse("env_bool", "FEATURE_ENABLED", value, str(default).lower())
                self.assertEqual(shell.returncode, 0, shell.stderr)
                self.assertEqual(shell.stdout, expected)
                self.assertEqual(str(env_bool(value, default=default)).lower(), expected)

    def test_same_invalid_boolean_inputs(self):
        for value in ("maybe", "2", "truthy"):
            with self.subTest(value=value):
                shell = bash_parse("env_bool", "FEATURE_ENABLED", value, "false")
                self.assertNotEqual(shell.returncode, 0)
                with self.assertRaises(ValueError):
                    env_bool(value, name="FEATURE_ENABLED")


class TestIntegerContractParity(unittest.TestCase):
    def test_same_positive_integer_inputs(self):
        for value, expected in ((None, 8080), ("", 8080), (" 8081 ", 8081), ("+42", 42), ("0007", 7)):
            with self.subTest(value=value):
                shell = bash_parse("env_positive_int", "PORT", value, 8080, 1, 65535)
                self.assertEqual(shell.returncode, 0, shell.stderr)
                self.assertEqual(int(shell.stdout), expected)
                self.assertEqual(
                    env_int(value, 8080, minimum=1, maximum=65535, clamp_minimum=False),
                    expected,
                )

    def test_same_invalid_integer_inputs(self):
        for value in ("abc", "12.5", "1_000", "١٢", "-1", "0", "65536"):
            with self.subTest(value=value):
                shell = bash_parse("env_positive_int", "PORT", value, 8080, 1, 65535)
                self.assertNotEqual(shell.returncode, 0)
                with self.assertRaises(ValueError):
                    env_int(
                        value,
                        8080,
                        name="PORT",
                        minimum=1,
                        maximum=65535,
                        clamp_minimum=False,
                    )

    def test_zero_padded_bounds_compare_numerically(self):
        # A zero-padded minimum/maximum must not be compared lexicographically
        # against the (leading-zero-stripped) value: "9" is >= "05" numerically
        # even though "9" > "05" as bare strings would already pass, but "9"
        # vs a padded maximum like "007" must correctly be rejected as above it.
        shell = bash_parse("env_positive_int", "PORT", "9", 8080, "05", 65535)
        self.assertEqual(shell.returncode, 0, shell.stderr)
        self.assertEqual(int(shell.stdout), 9)

        shell = bash_parse("env_positive_int", "PORT", "9", 8080, 1, "007")
        self.assertNotEqual(shell.returncode, 0)


class TestSecretContract(unittest.TestCase):
    def test_file_is_authoritative(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as secret_file:
            secret_file.write("  from-file\n")
            secret_file.flush()
            env = os.environ.copy()
            env.update(PASSWORD_SECRET="from-env", PASSWORD_SECRET_FILE=secret_file.name)
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; env_secret PASSWORD_SECRET && printf %s "$PASSWORD_SECRET"',
                    "bash",
                    str(SHELL_CONTRACT),
                ],
                env=env,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "from-file")

    def test_empty_file_fails(self):
        with tempfile.NamedTemporaryFile() as secret_file:
            env = os.environ.copy()
            env["PASSWORD_SECRET_FILE"] = secret_file.name
            result = subprocess.run(
                ["bash", "-c", 'source "$1"; env_secret PASSWORD_SECRET', "bash", str(SHELL_CONTRACT)],
                env=env,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is empty", result.stderr)


if __name__ == "__main__":
    unittest.main()
