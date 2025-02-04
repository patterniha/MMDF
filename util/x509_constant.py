from cryptography import x509
from cryptography.hazmat.primitives import hashes

algorithm_for_sign = hashes.SHA256()
san_is_critical = False
bc_extension = x509.BasicConstraints(ca=False, path_length=None)
bc_is_critical = True
key_usage_extension = x509.KeyUsage(True, False, False, False, False, False, False, False, False)
key_usage_is_critical = True
eku_extension = x509.ExtendedKeyUsage(
    [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])
eku_is_critical = False
subject_key_is_critical = False
authority_key_is_critical = False
certificate_policies_is_critical = False

certificate_policies_extension = x509.CertificatePolicies(
    [x509.PolicyInformation(policy_identifier=x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=None)])
