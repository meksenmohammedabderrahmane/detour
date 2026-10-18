# Third-Party Software Notices and Licenses

Detour incorporates or redistributes third-party components under their respective licenses.

---

## 1. Wintun Driver & Library (wintun.dll)
- **Copyright**: (c) 2018-2024 WireGuard LLC. All Rights Reserved.
- **Source**: https://www.wintun.net
- **License**: Wintun Prebuilt Binaries License.
- **Redistribution Right (Clause 3.d)**:
  > "3. RESTRICTIONS... You must not:
  > d. resell, redistribute, lease, rent, transfer, sublicense, or otherwise transfer rights of the Software without the prior written consent of WireGuard LLC, except insofar as the Software is distributed alongside other software that uses the Software only via the Permitted API;"
- **Application in Detour**: Detour distributes the official 64-bit `wintun.dll` alongside the application and consumes it exclusively through its exported C/Go interfaces (`WintunCreateAdapter`, `WintunOpenAdapter`, `WintunStartSession`, etc.) in compliance with Clause 3.d. The full text of the license is included in `_dist/wintun-LICENSE.txt` and installed to the application directory.

---

## 2. gVisor Network Stack
- **Copyright**: (c) Google LLC.
- **Source**: https://github.com/google/gvisor
- **License**: Apache License, Version 2.0.

---

## 3. tun2socks
- **Copyright**: (c) 2021-2024 xjasonlyu.
- **Source**: https://github.com/xjasonlyu/tun2socks
- **License**: GNU General Public License v3.0 / MIT components.

---

## 4. Go Standard Library & x/sys
- **Copyright**: (c) 2009 The Go Authors. All rights reserved.
- **Source**: https://github.com/golang/go and https://github.com/golang/sys
- **License**: BSD 3-Clause License.

---

## 5. WebView2 Go Bindings
- **Copyright**: (c) Microsoft Corporation and community contributors.
- **License**: MIT License.
