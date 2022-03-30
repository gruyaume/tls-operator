#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
import logging
import os
import re
import secrets
import string
from pathlib import Path

from ops.charm import ActionEvent, CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

from self_signed_certs_creator import (
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_pfx_package,
    generate_private_key,
)

logger = logging.getLogger(__name__)


class TLSOperatorCharm(CharmBase):

    _stored = StoredState()

    CERTIFICATE_PATH = "/etc/certs"
    CA_BASE_PATH = f"{CERTIFICATE_PATH}/ca"
    CA_PRIVATE_KEY_PATH = f"{CA_BASE_PATH}/ca.key"
    CA_CERTIFICATE_PATH = f"{CA_BASE_PATH}/ca.pem"

    def __init__(self, *args):
        super().__init__(*args)
        self._stored.set_default(pfx_password="")
        self.framework.observe(self.on.install, self._generate_ca_certificates)
        self.framework.observe(self.on.config_changed, self._generate_ca_certificates)
        self.framework.observe(self.on.get_pfx_password_action, self._on_get_pfx_password)
        self.framework.observe(
            self.on.certificate_relation_joined, self._generate_sever_certificates
        )

    def _generate_ca_certificates(self, event):
        ca_cert_subject = self.model.config.get("ca-cert-subject", None)
        if not ca_cert_subject or not self._subject_name_is_valid(ca_cert_subject):
            self.unit.status = BlockedStatus("`ca-cert-subject` must be set.")
            return

        ca_key_file = Path(self.CA_PRIVATE_KEY_PATH)
        ca_cert_file = Path(self.CA_CERTIFICATE_PATH)
        if self._file_exists(ca_key_file) and self._file_exists(ca_cert_file):
            logger.info("CA certificates are already created")
            self.unit.status = ActiveStatus()
            return

        logger.info(f"Will create a CA certificate with subject name {ca_cert_subject}")
        certificates = self._get_ca_certs(ca_cert_subject)
        self._create_directory(self.CA_BASE_PATH)
        self._write_to_files(self.CA_BASE_PATH, certificates)
        self.unit.status = ActiveStatus()

    def _generate_sever_certificates(self, event):
        ca_cert_subject = self.model.config.get("ca-cert-subject", None)
        if not ca_cert_subject or not self._subject_name_is_valid(ca_cert_subject):
            self.unit.status = WaitingStatus("`ca-cert-subject` must be set.")
            return

        certificate_subject_name = event.relation.data[event.app].get("subject-name", None)
        logger.info(f"Server subject name: {certificate_subject_name}")
        if not certificate_subject_name or not self._subject_name_is_valid(
            certificate_subject_name
        ):
            self.unit.status = WaitingStatus(
                f"`subject-name` can't be: {certificate_subject_name}"
            )
            event.defer()
            return

        server_certs_base_path = f"{self.CERTIFICATE_PATH}/{certificate_subject_name}"
        server_key_file = Path(f"{server_certs_base_path}/server.key")
        server_cert_file = Path(f"{server_certs_base_path}/server.pem")
        if self._file_exists(server_key_file) and self._file_exists(server_cert_file):
            logger.info("Server certificates are already created")

        else:
            ca_key_file = Path(self.CA_PRIVATE_KEY_PATH)
            ca_cert_file = Path(self.CA_CERTIFICATE_PATH)
            ca_private_key = self._load_from_file(ca_key_file)
            ca_certificate = self._load_from_file(ca_cert_file)
            certificates = self._get_server_certs(
                subject_name=certificate_subject_name,
                ca_private_key=ca_private_key,
                ca_certificate=ca_certificate,
            )
            self._create_directory(server_certs_base_path)
            self._write_to_files(server_certs_base_path, certificates)
        private_key = self._load_from_file(server_key_file)
        certificate = self._load_from_file(server_cert_file)
        self._pass_certs_to_relationship(event, private_key, certificate)

    def _pass_certs_to_relationship(
        self, event, server_private_key: bytes, server_certificate: bytes
    ):
        event.relation.data[self.app].update(
            {
                "server-key": self._encode_in_base64(server_private_key),
                "server-certificate": self._encode_in_base64(server_certificate),
            }
        )

    @staticmethod
    def _load_from_file(file_path: Path) -> bytes:
        with open(file_path, "rb") as pem_in:
            pem_lines = pem_in.read()
        return pem_lines

    @staticmethod
    def _create_directory(path: str):
        try:
            os.mkdir(path)
        except FileExistsError:
            pass

    @staticmethod
    def _write_to_files(directory: str, data: dict):
        for item in data:
            file_name = f"{directory}/{item}"
            with open(file_name, "wb") as pem_out:
                pem_out.write(data[item])

    @staticmethod
    def _subject_name_is_valid(ca_cert_subject: str) -> bool:
        match = re.match("^[a-zA-Z0-9][a-zA-Z0-9-.]+[a-zA-Z0-9]$", ca_cert_subject)
        if match:
            return True
        else:
            return False

    @staticmethod
    def _file_exists(file_path: Path) -> bool:
        if file_path.is_file():
            return True
        else:
            return False

    @staticmethod
    def _get_ca_certs(subject_name: str) -> dict:
        """
        Generates certificates:
            1. Generates CA private key
            2. Generate CA certificate
        """
        logger.info("Creating CA certificates...")
        ca_private_key = generate_private_key()
        ca_certificate = generate_ca(
            private_key=ca_private_key,
            subject=subject_name,
        )

        return {
            "ca.key": ca_private_key,
            "ca.pem": ca_certificate,
        }

    def _get_server_certs(
        self, subject_name: str, ca_certificate: bytes, ca_private_key: bytes
    ) -> dict:
        """
        Generates certificates:
            1. Generate server private key
            2. Generate CSR
            3. Generate server certificate
            4. Generate PFX file
        """
        logger.info("Creating server certificates...")
        server_private_key = generate_private_key()
        server_csr = generate_csr(
            private_key=server_private_key,
            subject=subject_name,
        )
        server_certificate = generate_certificate(
            csr=server_csr,
            ca=ca_certificate,
            ca_key=ca_private_key,
        )
        server_pfx = generate_pfx_package(
            private_key=server_private_key,
            certificate=server_certificate,
            password=self._get_pfx_password(),
        )

        return {
            "server.key": server_private_key,
            "server.pem": server_certificate,
            "server.pfx": server_pfx,
        }

    @property
    def _namespace(self) -> str:
        return self.model.name

    def _on_get_pfx_password(self, event: ActionEvent) -> None:
        event.set_results({"pfx-password": self._get_pfx_password()})

    def _get_pfx_password(self) -> str:
        """Returns the password for the pfx file."""
        if not self._stored.pfx_password:
            self._stored.pfx_password = self._generate_password()

        return self._stored.pfx_password

    @staticmethod
    def _generate_password() -> str:
        """Generates a random 12 character password."""
        chars = string.ascii_letters + string.digits
        return "".join(secrets.choice(chars) for _ in range(12))

    @staticmethod
    def _encode_in_base64(byte_string: bytes) -> str:
        """Encodes given byte string in Base64"""
        return base64.b64encode(byte_string).decode("utf-8")


if __name__ == "__main__":
    main(TLSOperatorCharm)
