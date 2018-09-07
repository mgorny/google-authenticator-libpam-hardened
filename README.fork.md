# Information on google-authenticator-libpam fork

## Why fork?

This fork was created in order to improve the Google Authenticator libpam module
for use on Gentoo Infrastructure.  It aims to solve a few design issues,
and to improve HOTP and TOTP support beyond what Google's mobile application
supports.

The road of forking has been chosen for two reasons.  Firstly, because
the current maintainer believes in bundling a private implementation of HOTP
and TOTP, including a bundled implementation of HMAC-SHA1 and a bundled
implementation of SHA-1.  Secondly, because of Google's privacy-infringing
requirements for signing the CLA.

## Design changes

The following important design changes have been made:

* The setup program no longer prints an URL sending the secret to Google's
  QRcode rendering service (which could incidentally expose the secret not only
  to Google but also e.g. to thumbnail rendering services).

* HOTP and TOTP are now implemented using external liboath (from [oath-toolkit])
  rather than using custom private implementation with bundled HMAC-SHA1.

* The qrencode library is used as a regular linked library rather than loaded
  dynamically (which improves compatibility).

[oath-toolkit]: http://www.nongnu.org/oath-toolkit/

## Bug fixes

The following issues have been additionally fixed:

* The build system is now fully autotools-compliant, including a working
  `make dist` target.

* The QRcode has been fixed to include the TOTP period (if other than default).

* The setup step now displays meaningful verification codes rather than useless
  i=0 code printed before.

## Enhancements

* Alternate digit counts are supported (6-8).

* SHA-2 algorithms are supported for the TOTP HMAC (SHA256 and SHA512).
