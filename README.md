# MMDF(Man in the Middle + Domain Fronting)
MMDF is a DPI circumvention method without using any server.

it replaces the main-sni with a random/user-defined sni in the tls-client-hello for **any** tls-request.

this is done with "Instant Certificate" technique (datails: https://github.com/XTLS/Xray-core/issues/4313#issuecomment-2613963340).

the only way to block MMDF is to block the IP,

but blocking the IP will cause all services behind that IP to stop working,

so MMDF is **UNBLOCKABLE**.

///

MMDF is designed to work with xray-core.(or any tools that support trojan inbound/outbound)

MMDF only communicates with Xray-core, it receive the data from xray-core, and after processing, forwards the data to xray-core.

currently, only trojan inbound/outbound is implemented in MMDF.

an example of xray-config for use with MMDF: [example_xray_config_for_MMDF](https://github.com/patterniha/MMDF/blob/main/Xray-core_config.jsonc)

if "fake_sni" is "random" in MMDF-config, a different random sni will be used for each connection

otherwise, the set value will be used for all connections.

if inbound-connection is not tls-connection MMDF redirect the connection to bypass_gateway without any change.

because xray-core can detect tls-connections and we only redirect tls-connections to MMDF, bypass_gateway is not used.

if MMDF show outbound ssl error: most likely, that website does not allow domain fronting.(see: [Usage and Limitation](https://github.com/patterniha/MMDF/tree/main?tab=readme-ov-file#usage-and-limitation), [Alternatives](https://github.com/patterniha/MMDF/blob/main/README.md#alternatives))

if MMDF show inbound ssl error: most likely, you did not import the self-signed certificate correctly into the system/browser/MMDF-config.


## Requirements
1. xray-core(v2rayng in android)
2. python with "cryptography" package
3. a self-signed certificate(must be imported into 1. system 2. browser 3. MMDF-config)

## Self-Signed certificate
for MMDF to work properly you need a "self-signed certificate" that must be imported into system and browser as a "Trusted-Root-Certification-Authorities".(reason: https://github.com/XTLS/Xray-core/issues/4313#issuecomment-2613963340)

the certificate must be "CA" and the certificate key-usages must include "Certificate Signing" and "CRL Signing".

you must also specify the path to the certificate and its private key in the MMDF-config.

if MMDF show inbound ssl error: most likely you did not import the certificate correctly into the system/browser/MMDF-config.

you can create self-signed-certificate with "openssl" commands or use online websites like: https://regery.com/en/security/ssl-tools/self-signed-certificate-generator and https://certificatetools.com.

(These sites are the first search results on google when you search: "create online self signed certificate", so these sites are most likely safe.)

## Full setup tutorial
1. create self-signed certificate with a desired name from https://regery.com/en/security/ssl-tools/self-signed-certificate-generator and download both the certificate and the private-key.

   **WARNING: Don't use an unknown certificate, just create your own self-signed certificate and use it.**
2. set the certificate and the private-key path in MMDF-config.
3. import the certificate into the system and browser:
   * **Android**:

     for Android, you only need to import the certificate into the system:
     Setting -> Security and privacy -> More security settings -> Install from device storage -> CA Certificate -> Install anyway -> Select the Certificate file on your storage.

     if successfully imported, you can view the certificate in: Setting -> Security and privacy -> More security settings -> View security certificates -> User.

    * **Windows**:
  
      in windows you need to import the certificate into both system and browser:
      * system:
        right click on the certificate -> Install certificate -> Local machine -> Place all certificates in the following store -> select "Trusted Root Certification Authorities"
      * browser(chrome):
        Settings -> Privacy and security -> Security -> Manage certificates -> Manage imported certificates from Windows -> Trusted Root Certification Authorities -> Import -> select the certificate file -> Place all certificates in the following store -> select "Trusted Root Certification Authorities"

    * **Others**:

      see: [SSL Certificates](https://www.charlesproxy.com/documentation/using-charles/ssl-certificates/)
        
4. download xray-core with Loyalsoldier GeoFiles:

   https://github.com/XTLS/Xray-core/releases

   https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat

   https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat

   replace the default geoip and geosite files with Loyalsoldier geoip and geosite files.(in v2rayng Loyalsoldier GeoFiles are the default, so you don't need to do this)

5. Install python with "cryptography" package(pip install cryptography)(if it gives an error in android try: pkg/apt install python-cryptography) 

6. run the xray-core(v2rayng in android) and "python main.py"

   an example of xray-config for use with MMDF: [example_xray_config_for_MMDF](https://github.com/patterniha/MMDF/blob/main/Xray-core_config.jsonc)

7. MMDF only communicates with Xray-core, so you only need to set the browser socks5 to xray-core-socks5-inbound: 127.0.0.1:10808 (in v2rayng this is the default socks5 port, so you don't need to do anything).

# Usage and Limitation
except in cases where the IP is blocked, MMDF bypasses the GFW.

MMDF does not change the IP, so it doesn't help with services that have Sanctioned Iran.

in android, only browsers support user-certificate, other apps must have added user-certificate-support to the app's manifest.([link1](https://stackoverflow.com/questions/4461360/how-to-install-trusted-ca-certificate-on-android-device), [link2](https://stackoverflow.com/questions/56295458/how-to-trust-a-user-added-certificate-in-android), [link3](https://www.charlesproxy.com/documentation/using-charles/ssl-certificates/))

also, some services do not allow domain fronting, so for a "reliable internet" you should only route websites-that-allow-domain-fronting to MMDF.

if MMDF show outbound ssl error: most likely, that website does not allow domain fronting.

* **websites that allow domain fronting:**

   - almost all google services (google, youtube, ...)
  
   - almost all websites behind fastly

   - all meta services (facebook, instagram, whatsapp, ...)

   - twitter, reddit, github, netflix, ...

* **websites that **do not allow** domain fronting:**

   - almost all websites behind cloudflare and cloudfront

   - all websites behind arvancloud (unless fake-sni is behind arvancloud too)

   - twitch, soundcloud, ...


# Security concerns
as mentioned, never use an unknown certificate.

**WARNING**: because of the complexity of implementation, currently certificate validation is not performed between MMDF and the target server, and will be added soon.

