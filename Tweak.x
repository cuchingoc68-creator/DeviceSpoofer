/*
 * DeviceSpoofer — iOS Jailbreak Tweak
 * Hook tất cả device identifier APIs
 * Áp dụng cho mọi app trên thiết bị
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <AdSupport/AdSupport.h>
#include <dlfcn.h>

// ═══════════════════════════════════════════════════
//  FAKE PROFILE — lưu vào plist, nhất quán mỗi phiên
//  Xóa file để regenerate profile mới
// ═══════════════════════════════════════════════════
#define PLIST_PATH @"/var/mobile/Library/Preferences/com.devicespoofer.profile.plist"

static NSMutableDictionary *_profile = nil;

static NSMutableDictionary *getProfile() {
    if (!_profile) {
        _profile = [NSMutableDictionary dictionaryWithContentsOfFile:PLIST_PATH]
                   ?: [NSMutableDictionary new];
    }
    return _profile;
}

static NSString *getOrCreate(NSString *key) {
    NSMutableDictionary *p = getProfile();
    if (!p[key]) {
        p[key] = [[NSUUID UUID] UUIDString];
        [p writeToFile:PLIST_PATH atomically:YES];
    }
    return p[key];
}

static NSString *getOrCreateAlpha(NSString *key, int len) {
    NSMutableDictionary *p = getProfile();
    if (!p[key]) {
        NSString *uuid = [[NSUUID UUID] UUIDString];
        // Lấy hex không có dấu gạch
        uuid = [uuid stringByReplacingOccurrencesOfString:@"-" withString:@""];
        if ((int)uuid.length > len) uuid = [uuid substringToIndex:len];
        p[key] = [[@"C" stringByAppendingString:uuid] uppercaseString];
        [p writeToFile:PLIST_PATH atomically:YES];
    }
    return p[key];
}

// ═══════════════════════════════════════════════════
//  HOOK 1: UIDevice — IDFV, tên máy, model, iOS ver
// ═══════════════════════════════════════════════════
%hook UIDevice

- (NSUUID *)identifierForVendor {
    NSString *fake = getOrCreate(@"idfv");
    return [[NSUUID alloc] initWithUUIDString:fake];
}

- (NSString *)name {
    return @"iPhone";
}

- (NSString *)model {
    return @"iPhone";
}

- (NSString *)localizedModel {
    return @"iPhone";
}

- (NSString *)systemVersion {
    // Giữ iOS version thật để tránh break app
    return %orig;
}

%end

// ═══════════════════════════════════════════════════
//  HOOK 2: ASIdentifierManager — IDFA (Advertising ID)
// ═══════════════════════════════════════════════════
%hook ASIdentifierManager

- (NSUUID *)advertisingIdentifier {
    NSString *fake = getOrCreate(@"idfa");
    return [[NSUUID alloc] initWithUUIDString:fake];
}

- (BOOL)isAdvertisingTrackingEnabled {
    return YES; // tracking enabled (bình thường hơn là disabled)
}

%end

// ═══════════════════════════════════════════════════
//  HOOK 3: DeviceCheck — bypass hardware token
//  Apple's DeviceCheck API — Grok dùng để nhớ "trial used"
// ═══════════════════════════════════════════════════
%hook DCDevice

- (void)generateTokenWithCompletionHandler:(void (^)(NSData *token, NSError *error))completionHandler {
    // Trả về nil token → Grok không lấy được hardware fingerprint
    if (completionHandler) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completionHandler(nil, nil);
        });
    }
}

%end

// ═══════════════════════════════════════════════════
//  HOOK 4: App Attest — bypass (iOS 14+)
// ═══════════════════════════════════════════════════
%hook DCAppAttestService

- (void)generateKeyWithCompletionHandler:(void (^)(NSString *keyId, NSError *error))completionHandler {
    if (completionHandler) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completionHandler(nil, nil);
        });
    }
}

- (void)attestKey:(NSString *)keyId
   clientDataHash:(NSData *)clientDataHash
completionHandler:(void (^)(NSData *attestationObject, NSError *error))completionHandler {
    if (completionHandler) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completionHandler(nil, nil);
        });
    }
}

%end

// ═══════════════════════════════════════════════════
//  HOOK 5: MobileGestalt — UDID, Serial, IMEI
//  Private C function — cần MSHookFunction
// ═══════════════════════════════════════════════════
typedef id (*MGCopyAnswerT)(CFStringRef key);
static MGCopyAnswerT orig_MGCopyAnswer = NULL;

static id hooked_MGCopyAnswer(CFStringRef key) {
    @autoreleasepool {
        NSString *k = (__bridge NSString *)key;

        if ([k isEqualToString:@"UniqueDeviceID"] ||
            [k isEqualToString:@"UniqueDeviceIDData"]) {
            NSString *fake = getOrCreate(@"udid");
            return [fake stringByReplacingOccurrencesOfString:@"-" withString:@""];
        }

        if ([k isEqualToString:@"SerialNumber"]) {
            return getOrCreateAlpha(@"serial", 11);
        }

        if ([k isEqualToString:@"DeviceName"] ||
            [k isEqualToString:@"UserAssignedDeviceName"]) {
            return @"iPhone";
        }

        if ([k isEqualToString:@"InternationalMobileEquipmentIdentity"]) {
            return getOrCreateAlpha(@"imei", 14);
        }
    }
    return orig_MGCopyAnswer ? orig_MGCopyAnswer(key) : nil;
}

// ═══════════════════════════════════════════════════
//  HOOK 6: NSURLRequest — spoof device headers
//  X/Twitter SDK gửi device ID trong HTTP headers
// ═══════════════════════════════════════════════════
%hook NSMutableURLRequest

- (void)setValue:(NSString *)value forHTTPHeaderField:(NSString *)field {
    NSString *lower = [field lowercaseString];
    NSArray *deviceHeaders = @[
        @"x-twitter-client-deviceid",
        @"x-b3-deviceid",
        @"x-client-deviceid",
        @"x-device-id",
        @"x-udid",
    ];
    for (NSString *h in deviceHeaders) {
        if ([lower isEqualToString:h]) {
            value = getOrCreate(@"idfv"); // thay bằng fake IDFV
            break;
        }
    }
    %orig(value, field);
}

%end

// ═══════════════════════════════════════════════════
//  CONSTRUCTOR — hook C functions khi load
// ═══════════════════════════════════════════════════
%ctor {
    %init;

    // Hook MobileGestalt
    void *libMG = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
    if (!libMG) {
        libMG = dlopen("/var/jb/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
    }
    if (libMG) {
        void *sym = dlsym(libMG, "MGCopyAnswer");
        if (sym) {
            MSHookFunction(sym,
                           (void *)hooked_MGCopyAnswer,
                           (void **)&orig_MGCopyAnswer);
        }
    }
}
