"""Tests for reconforge.core.validators."""

from pathlib import Path

import pytest

from reconforge.core.config import ScanConfig
from reconforge.core.exceptions import (
    InvalidOutputError,
    InvalidPortRangeError,
    InvalidTargetError,
    InvalidWordlistError,
)
from reconforge.core.validators import (
    validate_enum_config,
    validate_output,
    validate_pscan_config,
    validate_port_range,
    validate_target,
    validate_wordlist,
)

# --- validate_target ---------------------------------------------------


def test_validate_target_accepts_valid_hostname():
    pass


def test_validate_target_accepts_valid_ip():
    pass


def test_validate_target_rejects_invalid_target():
    pass


# --- validate_port_range ------------------------------------------------


def test_validate_port_range_accepts_valid_range():
    pass


def test_validate_port_range_accepts_valid_list():
    pass


def test_validate_port_range_rejects_out_of_bounds():
    pass


def test_validate_port_range_rejects_invalid_format():
    pass


# --- validate_wordlist ---------------------------------------------------


def test_validate_wordlist_accepts_valid_file(tmp_path):
    pass


def test_validate_wordlist_rejects_empty_file(tmp_path):
    pass


def test_validate_wordlist_rejects_directory(tmp_path):
    pass


# --- validate_output ------------------------------------------------------


def test_validate_output_accepts_writable_path(tmp_path):
    pass


def test_validate_output_rejects_missing_parent_dir():
    pass


# --- validate_pscan_config / validate_enum_config (orchestrators) --------


def test_validate_pscan_config_runs_all_checks():
    pass


def test_validate_enum_config_runs_all_checks():
    pass