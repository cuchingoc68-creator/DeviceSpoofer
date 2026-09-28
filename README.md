# DeviceSpoofer

iOS jailbreak tweak — bypass device fingerprinting cho Grok và mọi app.

## Hook gì?
- **IDFV** (identifierForVendor) → UUID giả nhất quán
- **IDFA** (advertisingIdentifier) → UUID giả
- **DeviceCheck** → nil (bypass hardware token)
- **App Attest** → nil (bypass)
- **MobileGestalt** → UDID/Serial/IMEI giả
- **HTTP Headers** → spoof x-twitter-client-deviceid

## Cài đặt
1. Download `.deb` từ GitHub Actions artifacts
2. Chuyển vào iPhone (AirDrop hoặc tool)
3. Sileo → cài từ file
4. Respring

## Reset profile (tạo device identity mới)
SSH vào iPhone:
```
rm /var/mobile/Library/Preferences/com.devicespoofer.profile.plist
killall -9 SpringBoard
```

## Build thủ công
```
make package FINALPACKAGE=1
```
