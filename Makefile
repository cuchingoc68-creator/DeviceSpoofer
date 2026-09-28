ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:15.0

INSTALL_TARGET_PROCESSES = SpringBoard

TWEAK_NAME = DeviceSpoofer

DeviceSpoofer_FILES          = Tweak.x
DeviceSpoofer_CFLAGS         = -fobjc-arc -Wno-deprecated-declarations
DeviceSpoofer_FRAMEWORKS     = UIKit Foundation AdSupport
DeviceSpoofer_PRIVATE_FRAMEWORKS = DeviceCheck
DeviceSpoofer_LIBRARIES      = substrate

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
