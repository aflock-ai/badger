//go:build darwin && cgo

#import <Foundation/Foundation.h>
#import <Security/SecTask.h>
#import <Virtualization/Virtualization.h>

int hc_vz_supported(void) {
    @autoreleasepool {
        if (@available(macOS 11.0, *)) {
            return [VZVirtualMachine isSupported] ? 1 : 0;
        }
        return 0;
    }
}

int hc_vz_entitlement(void) {
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) return -1;
    CFErrorRef error = NULL;
    CFTypeRef value = SecTaskCopyValueForEntitlement(task, CFSTR("com.apple.security.virtualization"), &error);
    int result = -1;
    if (!error) {
        if (!value) result = 0;
        else if (CFGetTypeID(value) == CFBooleanGetTypeID()) result = CFBooleanGetValue(value) ? 1 : 0;
    }
    if (value) CFRelease(value);
    if (error) CFRelease(error);
    CFRelease(task);
    return result;
}
