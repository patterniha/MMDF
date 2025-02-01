# MMDF
MMDF(Man in the Middle + Domain Fronting) is a DPI circumvention method.(like fragment and noise)

MMDF replace the main-sni with a random/user-defined sni in the tls-client-hello.(datails: https://github.com/XTLS/Xray-core/issues/4313#issuecomment-2613963340)

# Usage:
MMDF is designed to work with xray-core.(or any tools that support trojan inbound/outbound)

MMDF only communicates with Xray-core, MMDF receive the data from xray-core, and after processing, forwards the data to xray-core.

currently, only trojan inbound/outbound is implemented in MMDF.

an example of xray-config for use with MMDF: https://github.com/patterniha/xray_configs/blob/main/example_xray_config_for_MMDF

in MMDF-config if "fake_sni" is "random", a different random sni will be used for each connection
otherwise, the set value will be used for all connections.


## Requirements:
1. xray-core(v2rayng in android)
2. python with "cryptography" package(pip install cryptography)(you need termux to install python in android)
3. a self-signed certificate(must be imported into 1. system 2. browser 3. MMDF-config)

## Self-Signed certificate:
for MMDF to work properly you need a "self-signed certificate" that must be imported into system and browser as a "Trusted-Root-Certification-Authorities".(reason: https://github.com/XTLS/Xray-core/issues/4313#issuecomment-2613963340)

the certificate must be "CA" and the certificate key-usages must include "Certificate Signing" and "CRL Signing".

you must also specify the path to the certificate and its private key in the MMDF-config.

you can create self-signed-certificate with openssl commands or use online websites like: https://regery.com/en/security/ssl-tools/self-signed-certificate-generator and https://certificatetools.com.

(These sites are the first search results on Google when you search: "create online self signed certificate", so these sites are probably safe.)

## Full setup tutorial:
1. create self-signed certificate with a desired name from https://regery.com/en/security/ssl-tools/self-signed-certificate-generator and download both the certificate and the private-key.

   **WARNING: Don't use an unknown certificate, just create your own self-signed certificate and use it.**
2. set the certificate and the private-key path in MMDF-config.
3. import the certificate to the system and browser
   * **Android**:

     for Android, you only need to import the certificate into the system:
     Setting -> Security and privacy -> More security settings -> Install from device storage -> CA Certificate -> Install anyway -> Select the Certificate file on your storage.
     if successfully imported, you can view the certificate in: Setting -> Security and privacy -> More security settings -> View security certificates -> User.

    * **windows**:
  
      in windows you need to import the certificate into both system and browser:
      * system:
        right click on the certificate -> Install certificate -> Local machine -> Place all certificates in the following store -> select "Trusted Root Certification Authorities"
      * browser(chrome):
        Settings -> Privacy and security -> Security -> Manage certificates -> Manage imported certificates from Windows -> Trusted Root Certification Authorities -> Import -> select the certificate file -> Place all certificates in the following store -> select "Trusted Root Certification Authorities"
        
4. download xray-core with Loyalsoldier GeoFiles:
   https://github.com/XTLS/Xray-core/releases
   https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
   https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
   replace the default geoip and geosite files with Loyalsoldier geoip and geosite files.(in v2rayng Loyalsoldier GeoFiles are the default, so you don't need to do this)

5. Install python with "cryptography" package(pip install cryptography)

6. run the xray-core(v2rayng in android) and "python main.py"
   an example of xray-config for use with MMDF: https://github.com/patterniha/xray_configs/blob/main/example_xray_config_for_MMDF

7. MMDF only communicates with Xray-core, so you only need to set the browser socks5 to: 127.0.0.1:10808 (in v2rayng this is the default socks5 port, so you don't need to do anything).

# Limitation:
except in cases where the IP is blocked or the server does not allow domain fronting, MMDF bypasses the GFW.

* some websites that **allow** domain fronting(Although the IP of some of them may be blocked):

  all google services(google,youtube,...)

  almost all independent websites

  twitter

  reddit

  meta(facebook, instagram, whatsapp)

  telegram

  ...

* some websites that **do not allow** domain fronting:

  almost all websites behind cloudflare

  microsoft websites

  tiktok

  twitch

  soundcloud

  ...

# Security concerns:
first, as mentioned, never use an unknown certificate.

currently certificate validation is not performed between MMDF and the target server.

If this project is merged with Xray-core, certificate validation will definitely be implemented.
