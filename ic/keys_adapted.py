from ecdsa import der
from ecdsa import SigningKey
from six import b
from ecdsa.curves import Curve, Ed25519, Ed448
from ecdsa.util import (
    oid_ecPublicKey,
    oid_ecDH,
    oid_ecMQV,
)
import binascii

from hashlib import sha1

def normalise_bytes(buffer_object):
        """Cast the input into array of bytes."""
        return memoryview(buffer_object).cast("B")

class SigningKeyApapted(SigningKey):

    @classmethod
    def from_der(cls, string, hashfunc=sha1, valid_curve_encodings=None):
        """
        Initialise from key stored in :term:`DER` format.

        The DER formats supported are the un-encrypted RFC5915
        (the ssleay format) supported by OpenSSL, and the more common
        un-encrypted RFC5958 (the PKCS #8 format).

        Both formats contain an ASN.1 object following the syntax specified
        in RFC5915::

            ECPrivateKey ::= SEQUENCE {
              version        INTEGER { ecPrivkeyVer1(1) }} (ecPrivkeyVer1),
              privateKey     OCTET STRING,
              parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
              publicKey  [1] BIT STRING OPTIONAL
            }

        `publicKey` field is ignored completely (errors, if any, in it will
        be undetected).

        Two formats are supported for the `parameters` field: the named
        curve and the explicit encoding of curve parameters.
        In the legacy ssleay format, this implementation requires the optional
        `parameters` field to get the curve name. In PKCS #8 format, the curve
        is part of the PrivateKeyAlgorithmIdentifier.

        The PKCS #8 format includes an ECPrivateKey object as the `privateKey`
        field within a larger structure:

            OneAsymmetricKey ::= SEQUENCE {
                version                   Version,
                privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
                privateKey                PrivateKey,
                attributes            [0] Attributes OPTIONAL,
                ...,
                [[2: publicKey        [1] PublicKey OPTIONAL ]],
                ...
            }

        The `attributes` and `publicKey` fields are completely ignored; errors
        in them will not be detected.

        :param string: binary string with DER-encoded private ECDSA key
        :type string: bytes like object
        :param valid_curve_encodings: list of allowed encoding formats
            for curve parameters. By default (``None``) all are supported:
            ``named_curve`` and ``explicit``.
            Ignored for EdDSA.
        :type valid_curve_encodings: :term:`set-like object`

        :raises MalformedPointError: if the length of encoding doesn't match
            the provided curve or the encoded values is too large
        :raises RuntimeError: if the generation of public key from private
            key failed
        :raises UnexpectedDER: if the encoding of the DER file is incorrect

        :return: Initialised SigningKey object
        :rtype: SigningKey
        """
        s = normalise_bytes(string)
        curve = None

        s, empty = der.remove_sequence(s)
        if empty != b(""):
            raise der.UnexpectedDER(
                "trailing junk after DER privkey: %s" % binascii.hexlify(empty)
            )

        version, s = der.remove_integer(s)

        # At this point, PKCS #8 has a sequence containing the algorithm
        # identifier and the curve identifier. The ssleay format instead has
        # an octet string containing the key data, so this is how we can
        # distinguish the two formats.
        if der.is_sequence(s):
            if version not in (0, 1):
                raise der.UnexpectedDER(
                    "expected version '0' or '1' at start of privkey, got %d"
                    % version
                )

            sequence, s = der.remove_sequence(s)
            algorithm_oid, algorithm_identifier = der.remove_object(sequence)

            if algorithm_oid in (Ed25519.oid, Ed448.oid):
                if algorithm_identifier:
                    raise der.UnexpectedDER(
                        "Non NULL parameters for a EdDSA key"
                    )
                key_str_der, _ = der.remove_octet_string(s)
                # Ignore the optional "attributes" and "publicKey" fields that come after.
                # if s:
                #     raise der.UnexpectedDER(
                #         "trailing junk inside the privateKey"
                #     )
                key_str, s = der.remove_octet_string(key_str_der)
                if s:
                    raise der.UnexpectedDER(
                        "trailing junk after the encoded private key"
                    )

                if algorithm_oid == Ed25519.oid:
                    curve = Ed25519
                else:
                    assert algorithm_oid == Ed448.oid
                    curve = Ed448

                return cls.from_string(key_str, curve, None)

            if algorithm_oid not in (oid_ecPublicKey, oid_ecDH, oid_ecMQV):
                raise der.UnexpectedDER(
                    "unexpected algorithm identifier '%s'" % (algorithm_oid,)
                )

            curve = Curve.from_der(algorithm_identifier, valid_curve_encodings)

            if empty != b"":
                raise der.UnexpectedDER(
                    "unexpected data after algorithm identifier: %s"
                    % binascii.hexlify(empty)
                )

            # Up next is an octet string containing an ECPrivateKey. Ignore
            # the optional "attributes" and "publicKey" fields that come after.
            s, _ = der.remove_octet_string(s)

            # Unpack the ECPrivateKey to get to the key data octet string,
            # and rejoin the ssleay parsing path.
            s, empty = der.remove_sequence(s)
            if empty != b(""):
                raise der.UnexpectedDER(
                    "trailing junk after DER privkey: %s"
                    % binascii.hexlify(empty)
                )

            version, s = der.remove_integer(s)

        # The version of the ECPrivateKey must be 1.
        if version != 1:
            raise der.UnexpectedDER(
                "expected version '1' at start of DER privkey, got %d"
                % version
            )

        privkey_str, s = der.remove_octet_string(s)

        if not curve:
            tag, curve_oid_str, s = der.remove_constructed(s)
            if tag != 0:
                raise der.UnexpectedDER(
                    "expected tag 0 in DER privkey, got %d" % tag
                )
            curve = Curve.from_der(curve_oid_str, valid_curve_encodings)

        # we don't actually care about the following fields
        #
        # tag, pubkey_bitstring, s = der.remove_constructed(s)
        # if tag != 1:
        #     raise der.UnexpectedDER("expected tag 1 in DER privkey, got %d"
        #                             % tag)
        # pubkey_str = der.remove_bitstring(pubkey_bitstring, 0)
        # if empty != "":
        #     raise der.UnexpectedDER("trailing junk after DER privkey "
        #                             "pubkeystr: %s"
        #                             % binascii.hexlify(empty))

        # our from_string method likes fixed-length privkey strings
        if len(privkey_str) < curve.baselen:
            privkey_str = (
                b("\x00") * (curve.baselen - len(privkey_str)) + privkey_str
            )
        return cls.from_string(privkey_str, curve, hashfunc)
